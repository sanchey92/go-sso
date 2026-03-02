package auth

import (
	"context"

	"go.uber.org/zap"

	"github.com/sanchey92/sso/internal/domain/model"
)

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
