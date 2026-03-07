package auth

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"

	"go.uber.org/zap"

	domainerrors "github.com/sanchey92/sso/internal/domain/errors"
	"github.com/sanchey92/sso/internal/domain/model"
)

const (
	minPasswordLen  = 8
	defaultAudience = "sso"

	verifyKeyPrefix   = "verify:"
	verificationTTL   = 24 * time.Hour
	verifyTokenLength = 32
)

type Hasher interface {
	Hash(password string) (string, error)
	Verify(password, encodedHash string) (bool, error)
}

type TokenService interface {
	GenerateToken(userID, audience string) (string, error)
}

type UserRepository interface {
	Create(ctx context.Context, user *model.User) error
	GetByEmail(ctx context.Context, email string) (*model.User, error)
	UpdateEmailVerified(ctx context.Context, userID string, verified bool) error
}

type RefreshTokenRepository interface {
	SaveToken(ctx context.Context, token *model.RefreshToken) error
	GetByHash(ctx context.Context, hash string) (*model.RefreshToken, error)
	Revoke(ctx context.Context, id string) error
	RevokeByFamilyID(ctx context.Context, familyID string) error
}

type CacheStore interface {
	Set(ctx context.Context, key, value string, ttl time.Duration) error
	Get(ctx context.Context, key string) (string, error)
	Delete(ctx context.Context, key string) error
}

type EmailSender interface {
	SendVerificationEmail(_ context.Context, toEmail, token string) error
}

type Service struct {
	hasher      Hasher
	tokenSrv    TokenService
	userRepo    UserRepository
	refreshRepo RefreshTokenRepository
	cache       CacheStore
	email       EmailSender
	accessTTL   time.Duration
	refreshTTL  time.Duration
	log         *zap.Logger
}

func New(
	h Hasher,
	ts TokenService,
	ur UserRepository,
	rr RefreshTokenRepository,
	cs CacheStore,
	es EmailSender,
	accessTTL, refreshTTL time.Duration,
	log *zap.Logger,
) *Service {
	return &Service{
		hasher:      h,
		tokenSrv:    ts,
		userRepo:    ur,
		refreshRepo: rr,
		cache:       cs,
		email:       es,
		accessTTL:   accessTTL,
		refreshTTL:  refreshTTL,
		log:         log,
	}
}

func (s *Service) Register(ctx context.Context, email, password string) (*model.User, error) {
	email = strings.ToLower(strings.TrimSpace(email))

	if err := validateEmail(email); err != nil {
		return nil, err
	}
	if err := validatePassword(password); err != nil {
		return nil, err
	}

	hash, err := s.hasher.Hash(password)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	user := model.NewUser(email, hash)

	if err = s.userRepo.Create(ctx, user); err != nil {
		return nil, fmt.Errorf("create user: %w", err)
	}

	token, err := generateRandomToken(verifyTokenLength)
	if err != nil {
		s.log.Error("failed to generate verification token", zap.Error(err))
		return user, nil
	}

	key := verifyKeyPrefix + token
	if err := s.cache.Set(ctx, key, user.ID, verificationTTL); err != nil {
		s.log.Error("failed to save verification token", zap.Error(err))
		return user, nil
	}

	if err := s.email.SendVerificationEmail(ctx, user.Email, token); err != nil {
		s.log.Error("failed to send verification email",
			zap.Error(err),
			zap.String("user_id", user.ID),
		)
	}

	s.log.Info("user registered", zap.String("user_id", user.ID))

	return user, nil
}

func (s *Service) VerifyEmail(ctx context.Context, token string) error {
	key := verifyKeyPrefix + token

	userID, err := s.cache.Get(ctx, key)
	if err != nil {
		if errors.Is(err, domainerrors.ErrKeyNotFound) {
			return domainerrors.ErrInvalidVerificationToken
		}
		return fmt.Errorf("get verification token: %w", err)
	}

	if err := s.userRepo.UpdateEmailVerified(ctx, userID, true); err != nil {
		return fmt.Errorf("update email verified: %w", err)
	}

	if err = s.cache.Delete(ctx, key); err != nil {
		s.log.Error("failed to delete verification token",
			zap.Error(err),
			zap.String("user_id", userID),
		)
	}
	s.log.Info("email verified", zap.String("user_id", userID))
	return nil
}

func (s *Service) Login(ctx context.Context, email, password string) (*model.TokenPair, error) {
	email = strings.ToLower(strings.TrimSpace(email))

	user, err := s.userRepo.GetByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, domainerrors.ErrUserNotFound) {
			return nil, domainerrors.ErrInvalidCredentials
		}
		return nil, fmt.Errorf("get user by email: %w", err)
	}

	match, err := s.hasher.Verify(password, user.PasswordHash)
	if err != nil {
		return nil, fmt.Errorf("verify password: %w", err)
	}
	if !match {
		return nil, domainerrors.ErrInvalidCredentials
	}

	if !user.EmailVerified {
		return nil, domainerrors.ErrEmailNotVerified
	}

	if user.Status != model.UserStatusActive {
		return nil, domainerrors.ErrInvalidCredentials
	}

	accessToken, err := s.tokenSrv.GenerateToken(user.ID, defaultAudience)
	if err != nil {
		return nil, fmt.Errorf("generate access token: %w", err)
	}

	familyID, err := generateUUID()
	if err != nil {
		return nil, fmt.Errorf("generate family id: %w", err)
	}

	refreshToken, err := s.GenerateRefreshToken(ctx, user.ID, familyID, "", nil)
	if err != nil {
		return nil, err
	}

	s.log.Info("user logged in", zap.String("user_id", user.ID))

	return &model.TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(s.accessTTL.Seconds()),
	}, nil
}

func (s *Service) RefreshTokens(ctx context.Context, refreshToken string) (*model.TokenPair, error) {
	tokenHash := hashToken(refreshToken)

	stored, err := s.refreshRepo.GetByHash(ctx, tokenHash)
	if err != nil {
		return nil, fmt.Errorf("get refresh token: %w", err)
	}
	if time.Now().After(stored.ExpiresAt) {
		return nil, domainerrors.ErrTokenExpired
	}

	if stored.Revoked {
		if revokeErr := s.refreshRepo.RevokeByFamilyID(ctx, stored.FamilyID); revokeErr != nil {
			return nil, fmt.Errorf("revoke token family: %w", revokeErr)
		}
		s.log.Warn("refresh token replay detected",
			zap.String("family_id", stored.FamilyID),
			zap.String("user_id", stored.UserID),
		)
		return nil, domainerrors.ErrTokenRevoked
	}

	if err = s.refreshRepo.Revoke(ctx, stored.ID); err != nil {
		return nil, fmt.Errorf("revoke current token: %w", err)
	}

	newAccessToken, err := s.tokenSrv.GenerateToken(stored.UserID, defaultAudience)
	if err != nil {
		return nil, fmt.Errorf("generate access token: %w", err)
	}

	newRefreshToken, err := s.GenerateRefreshToken(ctx, stored.UserID, stored.FamilyID, stored.ClientID, stored.Scopes)
	if err != nil {
		return nil, fmt.Errorf("generate refresh token: %w", err)
	}

	s.log.Info("tokens refreshed",
		zap.String("user_id", stored.UserID),
		zap.String("family_id", stored.FamilyID),
	)

	return &model.TokenPair{
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
		ExpiresIn:    int64(s.accessTTL.Seconds()),
	}, nil
}

func (s *Service) RevokeToken(ctx context.Context, rawToken string) error {
	tokenHash := hashToken(rawToken)

	stored, err := s.refreshRepo.GetByHash(ctx, tokenHash)
	if err != nil {
		return fmt.Errorf("get refresh token: %w", err)
	}
	if stored.Revoked {
		return nil
	}

	if err := s.refreshRepo.Revoke(ctx, stored.ID); err != nil {
		return fmt.Errorf("revoke token: %w", err)
	}

	s.log.Info("token revoked", zap.String("user_id", stored.UserID))
	return nil
}

func (s *Service) GenerateRefreshToken(ctx context.Context, userID, familyID, clientID string, scopes []string) (string, error) {
	rawToken, err := generateRandomToken(32)
	if err != nil {
		return "", fmt.Errorf("generate refresh token: %w", err)
	}
	refreshToken := &model.RefreshToken{
		TokenHash: hashToken(rawToken),
		UserID:    userID,
		FamilyID:  familyID,
		ClientID:  clientID,
		Scopes:    scopes,
		ExpiresAt: time.Now().Add(s.refreshTTL),
	}
	if err = s.refreshRepo.SaveToken(ctx, refreshToken); err != nil {
		return "", fmt.Errorf("save refresh token: %w", err)
	}

	return rawToken, nil
}

func validateEmail(email string) error {
	if email == "" {
		return fmt.Errorf("email: cannot be empty")
	}
	if _, err := mail.ParseAddress(email); err != nil {
		return fmt.Errorf("email: invalid format")
	}
	return nil
}

func validatePassword(password string) error {
	if len(password) < minPasswordLen {
		return fmt.Errorf("password: must be at least %d characters", minPasswordLen)
	}
	return nil
}
