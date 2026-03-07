package handler

import (
	"context"
	"net/http"

	"go.uber.org/zap"

	"github.com/sanchey92/sso/internal/domain/model"
)

type AuthService interface {
	Login(ctx context.Context, email, password string) (*model.TokenPair, error)
}

type AuthHandler struct {
	svc AuthService
	log *zap.Logger
}

func NewAuthHandler(svc AuthService, log *zap.Logger) *AuthHandler {
	return &AuthHandler{svc: svc, log: log}
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := decodeJSON(w, r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body", "INVALID_REQUEST")
		return
	}

	pair, err := h.svc.Login(r.Context(), req.Email, req.Password)
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

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}
