package userinfo

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"go.uber.org/zap"

	"github.com/sanchey92/sso/internal/adapter/driving/rest/httputil"
	"github.com/sanchey92/sso/internal/adapter/driving/rest/middleware"
	domainerrors "github.com/sanchey92/sso/internal/domain/errors"
	"github.com/sanchey92/sso/internal/domain/model"
)

const bearerPrefix = "Bearer "

type InfoProvider interface {
	GetUserInfo(ctx context.Context, accessToken string) (*model.UserInfo, error)
}

type Handler struct {
	svc InfoProvider
	log *zap.Logger
}

func NewHandler(svc InfoProvider, log *zap.Logger) *Handler {
	return &Handler{
		svc: svc,
		log: log,
	}
}

func (h *Handler) UserInfo(w http.ResponseWriter, r *http.Request) {
	token := extractBearerToken(r)
	if token == "" {
		w.Header().Set("WWW-Authenticate", `Bearer realm="sso"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	info, err := h.svc.GetUserInfo(r.Context(), token)
	if err != nil {
		h.handleError(w, r, err)
		return
	}

	httputil.RespondJSON(w, http.StatusOK, &infoResponse{
		Sub:           info.Sub,
		Email:         info.Email,
		EmailVerified: info.EmailVerified,
	})
}

type infoResponse struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
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
	case errors.Is(err, domainerrors.ErrTokenExpired):
		w.Header().Set("WWW-Authenticate",
			`Bearer realm="sso", error="invalid_token", error_description="The access token expired"`)
		w.WriteHeader(http.StatusUnauthorized)
	case errors.Is(err, domainerrors.ErrUserNotFound):
		w.Header().Set("WWW-Authenticate",
			`Bearer realm="sso", error="invalid_token", error_description="The user not found"`)
		w.WriteHeader(http.StatusUnauthorized)
	default:
		if isTokenError(err) {
			w.Header().Set("WWW-Authenticate",
				`Bearer realm="sso", error="invalid_token", error_description="The access token is invalid"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		h.log.Error("userinfo error",
			zap.Error(err),
			zap.String("request_id", middleware.GetRequestID(r.Context())),
		)
		httputil.RespondError(w, http.StatusInternalServerError, "internal server error", "INTERNAL_ERROR")
	}
}

func isTokenError(err error) bool {
	return errors.Is(err, domainerrors.ErrInvalidToken) ||
		strings.Contains(err.Error(), "validate token:")
}
