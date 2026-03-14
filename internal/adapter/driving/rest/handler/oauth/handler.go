package oauth

import (
	"context"

	"go.uber.org/zap"

	"github.com/sanchey92/sso/internal/domain/model"
)

type OAuthAuthorizeService interface {
	Authorize(ctx context.Context, params *model.AuthorizationCode) (code string, err error)
}

type Handler struct {
	svc OAuthAuthorizeService
	log *zap.Logger
}

func NewHandler(svc OAuthAuthorizeService, log *zap.Logger) *Handler {
	return &Handler{
		svc: svc,
		log: log,
	}
}
