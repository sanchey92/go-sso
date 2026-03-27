package mfa

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"go.uber.org/zap"

	"github.com/sanchey92/sso/internal/adapter/driving/rest/handler/httputil"
	"github.com/sanchey92/sso/internal/adapter/driving/rest/middleware"
	domainerrors "github.com/sanchey92/sso/internal/domain/errors"
	"github.com/sanchey92/sso/internal/domain/model"
)

const bearerPrefix = "Bearer "

type TOTPService interface {
	SetupTOTP(ctx context.Context, userID string) (string, error)
	VerifySetup(ctx context.Context, userID, code string) ([]string, error)
	DisableTOTP(ctx context.Context, userID, code string) error
}

type TokenValidator interface {
	ValidateToken(tokenStr string) (string, error)
}

type Completer interface {
	CompleteMFALogin(ctx context.Context, mfaToken, code string) (*model.TokenPair, error)
	CompleteMFARecovery(ctx context.Context, mfaToken, code string) (*model.TokenPair, error)
}

type Handler struct {
	totpSvc   TOTPService
	validator TokenValidator
	completer Completer
	log       *zap.Logger
}

func New(ts TOTPService, tv TokenValidator, c Completer, l *zap.Logger) *Handler {
	return &Handler{
		totpSvc:   ts,
		validator: tv,
		completer: c,
		log:       l,
	}
}

func (h *Handler) extractUserID(w http.ResponseWriter, r *http.Request) (string, bool) {
	token := extractBearerToken(r)
	if token == "" {
		w.Header().Set("WWW-Authenticate", `Bearer realm="sso"`)
		w.WriteHeader(http.StatusUnauthorized)
		return "", false
	}
	userID, err := h.validator.ValidateToken(token)
	if err != nil {
		w.Header().Set("WWW-Authenticate",
			`Bearer realm="sso", error="invalid_token", error_description="The access token is invalid"`)
		w.WriteHeader(http.StatusUnauthorized)
		return "", false
	}
	return userID, true
}

func extractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, bearerPrefix) {
		return ""
	}
	return auth[len(bearerPrefix):]
}

func (h *Handler) handleError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, domainerrors.ErrMFAAlreadyEnabled):
		httputil.RespondError(w, http.StatusConflict, "mfa already enabled", "MFA_ALREADY_ENABLED")
	case errors.Is(err, domainerrors.ErrMFANotEnabled):
		httputil.RespondError(w, http.StatusBadRequest, "mfa not enabled", "MFA_NOT_ENABLED")
	case errors.Is(err, domainerrors.ErrInvalidTOTPCode):
		httputil.RespondError(w, http.StatusBadRequest, "invalid totp code", "INVALID_TOTP_CODE")
	case errors.Is(err, domainerrors.ErrRecoveryCodeNotFound):
		httputil.RespondError(w, http.StatusBadRequest, "invalid code", "INVALID_CODE")
	case errors.Is(err, domainerrors.ErrInvalidMFAToken):
		httputil.RespondError(w, http.StatusUnauthorized, "invalid or expired mfa token", "INVALID_MFA_TOKEN")
	default:
		h.log.Error("mfa handler error",
			zap.Error(err),
			zap.String("request_id", middleware.GetRequestID(r.Context())),
		)
		httputil.RespondError(w, http.StatusInternalServerError, "internal server error", "INTERNAL_ERROR")
	}
}
