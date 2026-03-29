package token

import (
	"context"
	"errors"
	"net/http"

	"go.uber.org/zap"

	"github.com/sanchey92/sso/internal/adapter/driving/rest/httputil"
	"github.com/sanchey92/sso/internal/adapter/driving/rest/middleware"
	domainerrors "github.com/sanchey92/sso/internal/domain/errors"
	"github.com/sanchey92/sso/internal/domain/model"
)

type TokenService interface {
	RefreshTokens(ctx context.Context, refreshToken string) (*model.TokenPair, error)
	RevokeToken(ctx context.Context, refreshToken string) error
}

type Handler struct {
	svc TokenService
	log *zap.Logger
}

func NewHandler(svc TokenService, log *zap.Logger) *Handler {
	return &Handler{svc: svc, log: log}
}

func (h *Handler) Refresh(w http.ResponseWriter, r *http.Request) {
	var req refreshRequest
	if err := httputil.DecodeJSON(w, r, &req); err != nil {
		httputil.RespondError(w, http.StatusBadRequest, "invalid request body", "INVALID_REQUEST")
		return
	}
	pair, err := h.svc.RefreshTokens(r.Context(), req.RefreshToken)
	if err != nil {
		h.handleError(w, r, err)
		return
	}

	httputil.RespondJSON(w, http.StatusOK, &tokenResponse{
		AccessToken:  pair.AccessToken,
		RefreshToken: pair.RefreshToken,
		ExpiresIn:    pair.ExpiresIn,
	})
}

func (h *Handler) Revoke(w http.ResponseWriter, r *http.Request) {
	var req revokeRequest
	if err := httputil.DecodeJSON(w, r, &req); err != nil {
		httputil.RespondError(w, http.StatusBadRequest, "invalid request body", "INVALID_REQUEST")
		return
	}
	if err := h.svc.RevokeToken(r.Context(), req.RefreshToken); err != nil {
		h.handleError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) handleError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, domainerrors.ErrInvalidToken):
		httputil.RespondError(w, http.StatusUnauthorized, "invalid token", "INVALID_TOKEN")
	case errors.Is(err, domainerrors.ErrTokenExpired):
		httputil.RespondError(w, http.StatusUnauthorized, "token expired", "TOKEN_EXPIRED")
	case errors.Is(err, domainerrors.ErrTokenRevoked):
		httputil.RespondError(w, http.StatusUnauthorized, "token revoked", "TOKEN_REVOKED")
	default:
		h.log.Error("internal error",
			zap.Error(err),
			zap.String("request_id", middleware.GetRequestID(r.Context())),
		)
		httputil.RespondError(w, http.StatusInternalServerError, "internal server error", "INTERNAL_ERROR")
	}
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type revokeRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
}
