package user

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

type UserService interface {
	Register(ctx context.Context, email, password string) (*model.User, error)
	VerifyEmail(ctx context.Context, token string) error
	RequestPasswordReset(ctx context.Context, email string) error
	ResetPassword(ctx context.Context, token, newPassword string) error
}

type Handler struct {
	svc UserService
	log *zap.Logger
}

func NewHandler(svc UserService, log *zap.Logger) *Handler {
	return &Handler{svc: svc, log: log}
}

func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	var req registerRequest

	if err := httputil.DecodeJSON(w, r, &req); err != nil {
		httputil.RespondError(w, http.StatusBadRequest, "invalid request body", "INVALID_REQUEST")
		return
	}

	user, err := h.svc.Register(r.Context(), req.Email, req.Password)
	if err != nil {
		h.handleError(w, r, err)
		return
	}

	httputil.RespondJSON(w, http.StatusCreated, &registerResponse{
		UserID:  user.ID,
		Message: "user registered successfully",
	})
}

func (h *Handler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	var req verifyEmailRequest
	if err := httputil.DecodeJSON(w, r, &req); err != nil {
		httputil.RespondError(w, http.StatusBadRequest, "invalid request body", "INVALID_REQUEST")
		return
	}
	if req.Token == "" {
		httputil.RespondError(w, http.StatusBadRequest, "token is required", "VALIDATION_ERROR")
		return
	}

	if err := h.svc.VerifyEmail(r.Context(), req.Token); err != nil {
		h.handleError(w, r, err)
		return
	}
	httputil.RespondJSON(w, http.StatusOK, &messageResponse{
		Message: "email verified successfully",
	})
}

func (h *Handler) RequestPasswordReset(w http.ResponseWriter, r *http.Request) {
	var req resetPasswordRequestRequest
	if err := httputil.DecodeJSON(w, r, &req); err != nil {
		httputil.RespondError(w, http.StatusBadRequest, "invalid request body", "INVALID_REQUEST")
		return
	}

	if err := h.svc.RequestPasswordReset(r.Context(), req.Email); err != nil {
		h.handleError(w, r, err)
		return
	}

	httputil.RespondJSON(w, http.StatusOK, &messageResponse{
		Message: "if the email exists, a password reset link has been sent",
	})
}

func (h *Handler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	var req resetPasswordRequest
	if err := httputil.DecodeJSON(w, r, &req); err != nil {
		httputil.RespondError(w, http.StatusBadRequest, "invalid request body", "INVALID_REQUEST")
		return
	}
	if req.Token == "" {
		httputil.RespondError(w, http.StatusBadRequest, "token is required", "VALIDATION_ERROR")
		return
	}

	if err := h.svc.ResetPassword(r.Context(), req.Token, req.NewPassword); err != nil {
		h.handleError(w, r, err)
		return
	}

	httputil.RespondJSON(w, http.StatusOK, &messageResponse{
		Message: "password has been reset successfully",
	})
}

func (h *Handler) handleError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, domainerrors.ErrEmailAlreadyExists):
		httputil.RespondError(w, http.StatusConflict, "email already exists", "EMAIL_EXISTS")
	case errors.Is(err, domainerrors.ErrInvalidVerificationToken):
		httputil.RespondError(w, http.StatusBadRequest, "invalid or expired verification token", "INVALID_VERIFICATION_TOKEN")
	case errors.Is(err, domainerrors.ErrInvalidResetToken):
		httputil.RespondError(w, http.StatusBadRequest, "invalid or expired reset token", "INVALID_RESET_TOKEN")
	default:
		if errors.Unwrap(err) == nil {
			httputil.RespondError(w, http.StatusBadRequest, err.Error(), "VALIDATION_ERROR")
			return
		}
		h.log.Error("internal error",
			zap.Error(err),
			zap.String("request_id", middleware.GetRequestID(r.Context())),
		)
		httputil.RespondError(w, http.StatusInternalServerError, "internal server error", "INTERNAL_ERROR")
	}
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

type resetPasswordRequestRequest struct {
	Email string `json:"email"`
}

type resetPasswordRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

type messageResponse struct {
	Message string `json:"message"`
}
