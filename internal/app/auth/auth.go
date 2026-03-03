package auth

import (
	"context"
	"fmt"
	"net/mail"
	"strings"

	"go.uber.org/zap"

	"github.com/sanchey92/sso/internal/domain/model"
)

const minPasswordLen = 8

type Hasher interface {
	Hash(password string) (string, error)
	Verify(password, encodedHash string) (bool, error)
}

type UserRepository interface {
	Create(ctx context.Context, user *model.User) error
	GetByEmail(ctx context.Context, email string) (*model.User, error)
}

type Service struct {
	hasher   Hasher
	userRepo UserRepository
	log      *zap.Logger
}

func New(h Hasher, ur UserRepository, log *zap.Logger) *Service {
	return &Service{
		hasher:   h,
		userRepo: ur,
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

	s.log.Info("user registered", zap.String("user_id", user.ID))

	return user, nil
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
