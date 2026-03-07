package user

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
	"github.com/sanchey92/sso/pkg/crypto"
)

const (
	minPasswordLen  = 8
	verifyKeyPrefix = "verify:"
	verificationTTL = 24 * time.Hour
	verifyTokenLen  = 32
)

type UserRepository interface {
	Create(ctx context.Context, user *model.User) error
	GetByEmail(ctx context.Context, email string) (*model.User, error)
	UpdateEmailVerified(ctx context.Context, userID string, verified bool) error
}

type PasswordHasher interface {
	Hash(password string) (string, error)
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
	userRepo UserRepository
	hasher   PasswordHasher
	cache    CacheStore
	email    EmailSender
	log      *zap.Logger
}

func New(ur UserRepository, h PasswordHasher, cs CacheStore, es EmailSender, log *zap.Logger) *Service {
	return &Service{
		userRepo: ur,
		hasher:   h,
		cache:    cs,
		email:    es,
		log:      log,
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

	token, err := crypto.GenerateRandomToken(verifyTokenLen)
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
