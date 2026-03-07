package handler

import (
	"context"
	"net/http"

	"go.uber.org/zap"

	"github.com/sanchey92/sso/internal/domain/model"
)

type TokenService interface {
	RefreshTokens(ctx context.Context, refreshToken string) (*model.TokenPair, error)
	RevokeToken(ctx context.Context, refreshToken string) error
}

type TokenHandler struct {
	svc TokenService
	log *zap.Logger
}

func NewTokenHandler(svc TokenService, log *zap.Logger) *TokenHandler {
	return &TokenHandler{svc: svc, log: log}
}

func (h *TokenHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	var req refreshRequest
	if err := decodeJSON(w, r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body", "INVALID_REQUEST")
		return
	}
	pair, err := h.svc.RefreshTokens(r.Context(), req.RefreshToken)
	if err != nil {
		handleServiceError(w, r, err, h.log)
		return
	}

	respondJSON(w, http.StatusOK, &tokenResponse{
		AccessToken:  pair.AccessToken,
		RefreshToken: pair.RefreshToken,
		ExpiresIn:    pair.ExpiresIn,
	})
}

func (h *TokenHandler) Revoke(w http.ResponseWriter, r *http.Request) {
	var req revokeRequest
	if err := decodeJSON(w, r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body", "INVALID_REQUEST")
		return
	}
	if err := h.svc.RevokeToken(r.Context(), req.RefreshToken); err != nil {
		handleServiceError(w, r, err, h.log)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type revokeRequest struct {
	RefreshToken string `json:"refresh_token"`
}
