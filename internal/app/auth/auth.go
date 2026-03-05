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
}

type RefreshTokenRepository interface {
	Create(ctx context.Context, token *model.RefreshToken) error
}

type LoginResult struct {
	AccessToken  string //nolint:gosec // response DTO field, not a hardcoded secret
	RefreshToken string //nolint:gosec // response DTO field, not a hardcoded secret
	ExpiresIn    int64
}

type Service struct {
	hasher      Hasher
	tokenSrv    TokenService
	userRepo    UserRepository
	refreshRepo RefreshTokenRepository
	accessTTL   time.Duration
	refreshTTL  time.Duration
	log         *zap.Logger
}

func New(
	h Hasher,
	ts TokenService,
	ur UserRepository,
	rr RefreshTokenRepository,
	accessTTL, refreshTTL time.Duration,
	log *zap.Logger,
) *Service {
	return &Service{
		hasher:      h,
		tokenSrv:    ts,
		userRepo:    ur,
		refreshRepo: rr,
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

	s.log.Info("user registered", zap.String("user_id", user.ID))

	return user, nil
}

func (s *Service) Login(ctx context.Context, email, password string) (*LoginResult, error) {
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

	refreshToken, err := s.GenerateRefreshToken(ctx, user.ID, familyID)
	if err != nil {
		return nil, err
	}

	s.log.Info("user logged in", zap.String("user_id", user.ID))

	return &LoginResult{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(s.accessTTL.Seconds()),
	}, nil
}

func (s *Service) GenerateRefreshToken(ctx context.Context, userID, familyID string) (string, error) {
	rawToken, err := generateRandomToken(32)
	if err != nil {
		return "", fmt.Errorf("generate refresh token: %w", err)
	}
	refreshToken := &model.RefreshToken{
		TokenHash: hashToken(rawToken),
		UserID:    userID,
		FamilyID:  familyID,
		ExpiresAt: time.Now().Add(s.refreshTTL),
	}
	if err = s.refreshRepo.Create(ctx, refreshToken); err != nil {
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
