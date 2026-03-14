package oauth

import (
	"context"

	"go.uber.org/zap"

	"github.com/sanchey92/sso/internal/domain/model"
)

type OAuthorizer interface {
	Authorize(ctx context.Context, params *model.AuthorizationCode) (code string, err error)
}

type Exchanger interface {
	ExchangeCode(ctx context.Context, req *model.CodeExchangeRequest) (*model.TokenPair, error)
}

type Refresher interface {
	RefreshTokens(ctx context.Context, refreshToken string) (*model.TokenPair, error)
}

type Handler struct {
	oauth     OAuthorizer
	exchanger Exchanger
	refresher Refresher
	log       *zap.Logger
}

func NewHandler(oauth OAuthorizer, ex Exchanger, ref Refresher, log *zap.Logger) *Handler {
	return &Handler{
		oauth:     oauth,
		exchanger: ex,
		refresher: ref,
		log:       log,
	}
}
