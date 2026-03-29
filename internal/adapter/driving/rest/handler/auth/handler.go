package auth

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

type AuthService interface {
	Login(ctx context.Context, email, password string) (*model.LoginResult, error)
}

type Handler struct {
	svc AuthService
	log *zap.Logger
}

func NewHandler(svc AuthService, log *zap.Logger) *Handler {
	return &Handler{svc: svc, log: log}
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := httputil.DecodeJSON(w, r, &req); err != nil {
		httputil.RespondError(w, http.StatusBadRequest, "invalid request body", "INVALID_REQUEST")
		return
	}

	result, err := h.svc.Login(r.Context(), req.Email, req.Password)
	if err != nil {
		h.handleError(w, r, err)
		return
	}

	if result.MFAChallenge != nil {
		httputil.RespondJSON(w, http.StatusOK, &mfaChallengeResponse{
			MFARequired: true,
			MFAToken:    result.MFAChallenge.MFAToken,
		})
		return
	}

	httputil.RespondJSON(w, http.StatusOK, &tokenResponse{
		AccessToken:  result.Tokens.AccessToken,
		RefreshToken: result.Tokens.RefreshToken,
		ExpiresIn:    result.Tokens.ExpiresIn,
	})
}

func (h *Handler) handleError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, domainerrors.ErrInvalidCredentials):
		httputil.RespondError(w, http.StatusUnauthorized, "invalid credentials", "INVALID_CREDENTIALS")
	case errors.Is(err, domainerrors.ErrEmailNotVerified):
		httputil.RespondError(w, http.StatusForbidden, "email not verified", "EMAIL_NOT_VERIFIED")
	default:
		h.log.Error("internal error",
			zap.Error(err),
			zap.String("request_id", middleware.GetRequestID(r.Context())),
		)
		httputil.RespondError(w, http.StatusInternalServerError, "internal server error", "INTERNAL_ERROR")
	}
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
}

type mfaChallengeResponse struct {
	MFARequired bool   `json:"mfa_required"`
	MFAToken    string `json:"mfa_token"`
}
