package handler

import (
	"context"
	"net/http"

	"go.uber.org/zap"

	"github.com/sanchey92/sso/internal/domain/model"
)

type UserService interface {
	Register(ctx context.Context, email, password string) (*model.User, error)
	VerifyEmail(ctx context.Context, token string) error
	RequestPasswordReset(ctx context.Context, email string) error
	ResetPassword(ctx context.Context, token, newPassword string) error
}

type UserHandler struct {
	svc UserService
	log *zap.Logger
}

func NewUserHandler(svc UserService, log *zap.Logger) *UserHandler {
	return &UserHandler{svc: svc, log: log}
}

func (h *UserHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req registerRequest

	if err := decodeJSON(w, r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body", "INVALID_REQUEST")
		return
	}

	user, err := h.svc.Register(r.Context(), req.Email, req.Password)
	if err != nil {
		handleServiceError(w, r, err, h.log)
		return
	}

	respondJSON(w, http.StatusCreated, &registerResponse{
		UserID:  user.ID,
		Message: "user registered successfully",
	})
}

func (h *UserHandler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	var req verifyEmailRequest
	if err := decodeJSON(w, r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body", "INVALID_REQUEST")
		return
	}
	if req.Token == "" {
		respondError(w, http.StatusBadRequest, "token is required", "VALIDATION_ERROR")
		return
	}

	if err := h.svc.VerifyEmail(r.Context(), req.Token); err != nil {
		handleServiceError(w, r, err, h.log)
		return
	}
	respondJSON(w, http.StatusOK, &messageResponse{
		Message: "email verified successfully",
	})
}

type registerRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type registerResponse struct {
	UserID  string `json:"user_id"`
	Message string `json:"message"`
}

type verifyEmailRequest struct {
	Token string `json:"token"`
}
