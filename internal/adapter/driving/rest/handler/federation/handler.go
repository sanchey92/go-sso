package federation

import (
	"context"
	"errors"
	"net/http"

	"go.uber.org/zap"

	"github.com/sanchey92/sso/internal/adapter/driving/rest/handler/httputil"
	"github.com/sanchey92/sso/internal/adapter/driving/rest/middleware"
	domainerrors "github.com/sanchey92/sso/internal/domain/errors"
	"github.com/sanchey92/sso/internal/domain/model"
)

type Initiator interface {
	InitiateOAuth(ctx context.Context, provider string) (string, error)
}

type CallbackHandler interface {
	HandleCallback(ctx context.Context, provider, code, state string) (*model.TokenPair, error)
}

type Handler struct {
	initiator Initiator
	callback  CallbackHandler
	log       *zap.Logger
}

func NewHandler(init Initiator, cb CallbackHandler, log *zap.Logger) *Handler {
	return &Handler{
		initiator: init,
		callback:  cb,
		log:       log,
	}
}

func (h *Handler) handleError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, domainerrors.ErrProviderNotSupported):
		httputil.RespondError(w, http.StatusNotFound, "unknown identity provider", "PROVIDER_NOT_FOUND")

	case errors.Is(err, domainerrors.ErrInvalidOAuthState):
		httputil.RespondError(w, http.StatusBadRequest, "invalid or expired OAuth state", "INVALID_STATE")

	case errors.Is(err, domainerrors.ErrProviderEmailNotVerified):
		httputil.RespondError(w, http.StatusForbidden, "provider email is not verified", "EMAIL_NOT_VERIFIED")

	default:
		h.log.Error("federation error",
			zap.Error(err),
			zap.String("request_id", middleware.GetRequestID(r.Context())),
		)
		httputil.RespondError(w, http.StatusInternalServerError, "internal server error", "INTERNAL_ERROR")
	}
}
