package rest

import (
	"context"
	"net/http"

	"go.uber.org/zap"

	"github.com/sanchey92/sso/internal/domain/model"
)

type AuthService interface {
	Register(ctx context.Context, email, password string) (*model.User, error)
	Login(ctx context.Context, email, password string) (*model.TokenPair, error)
	RefreshTokens(ctx context.Context, refreshToken string) (*model.TokenPair, error)
	RevokeToken(ctx context.Context, refreshToken string) error
	VerifyEmail(ctx context.Context, token string) error
}

type AuthHandler struct {
	authSrv AuthService
	log     *zap.Logger
}

func NewAuthHandler(auth AuthService, log *zap.Logger) *AuthHandler {
	return &AuthHandler{authSrv: auth, log: log}
}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req registerRequest

	if err := decodeJSON(w, r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body", "INVALID_REQUEST")
		return
	}

	user, err := h.authSrv.Register(r.Context(), req.Email, req.Password)
	if err != nil {
		handleServiceError(w, r, err, h.log)
		return
	}

	respondJSON(w, http.StatusCreated, &registerResponse{
		UserID:  user.ID,
		Message: "user registered successfully",
	})
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := decodeJSON(w, r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body", "INVALID_REQUEST")
		return
	}

	pair, err := h.authSrv.Login(r.Context(), req.Email, req.Password)
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

func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	var req refreshRequest
	if err := decodeJSON(w, r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body", "INVALID_REQUEST")
		return
	}
	pair, err := h.authSrv.RefreshTokens(r.Context(), req.RefreshToken)
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

func (h *AuthHandler) Revoke(w http.ResponseWriter, r *http.Request) {
	var req revokeRequest
	if err := decodeJSON(w, r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body", "INVALID_REQUEST")
		return
	}
	if err := h.authSrv.RevokeToken(r.Context(), req.RefreshToken); err != nil {
		handleServiceError(w, r, err, h.log)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *AuthHandler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	var req verifyEmailRequest
	if err := decodeJSON(w, r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body", "INVALID_REQUEST")
		return
	}
	if req.Token == "" {
		respondError(w, http.StatusBadRequest, "token is required", "VALIDATION_ERROR")
		return
	}

	if err := h.authSrv.VerifyEmail(r.Context(), req.Token); err != nil {
		handleServiceError(w, r, err, h.log)
		return
	}
	respondJSON(w, http.StatusOK, &messageResponse{
		Message: "email verified successfully",
	})
}
