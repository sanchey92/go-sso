package handler

import (
	"context"
	"time"

	"go.uber.org/zap"

	ssov1 "github.com/sanchey92/sso/gen/sso/v1"
	"github.com/sanchey92/sso/internal/domain/model"
)

type TokenIntrospector interface {
	ValidateToken(tokenStr string) (*model.TokenClaims, error)
}

type UserGetter interface {
	GetByID(ctx context.Context, userID string) (*model.User, error)
}

type IntrospectionCache interface {
	Get(ctx context.Context, key string) (string, error)
	Set(ctx context.Context, key, value string, ttl time.Duration) error
}

type Handler struct {
	ssov1.UnimplementedSSOInternalServiceServer

	introspector TokenIntrospector
	users        UserGetter
	cache        IntrospectionCache
	cacheTTL     time.Duration
	log          *zap.Logger
}

func New(
	introspector TokenIntrospector,
	users UserGetter,
	cache IntrospectionCache,
	cacheTTL time.Duration,
	log *zap.Logger,
) *Handler {
	return &Handler{
		introspector: introspector,
		users:        users,
		cache:        cache,
		cacheTTL:     cacheTTL,
		log:          log,
	}
}
