package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"go.uber.org/zap"

	"github.com/sanchey92/sso/internal/adapter/driving/rest/middleware"
	domainerrors "github.com/sanchey92/sso/internal/domain/errors"
)

const maxBodySize = 1 << 20

type ErrorResponse struct {
	Error string `json:"error"`
	Code  string `json:"code"`
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
}

type messageResponse struct {
	Message string `json:"message"`
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		return fmt.Errorf("decode json: %w", err)
	}
	return nil
}

func respondJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if data != nil {
		_ = json.NewEncoder(w).Encode(data) //nolint:gosec // error writing response body is unrecoverable
	}
}

func respondError(w http.ResponseWriter, status int, msg, code string) {
	respondJSON(w, status, ErrorResponse{Error: msg, Code: code})
}

func handleServiceError(w http.ResponseWriter, r *http.Request, err error, log *zap.Logger) {
	switch {
	case errors.Is(err, domainerrors.ErrEmailAlreadyExists):
		respondError(w, http.StatusConflict, "email already exists", "EMAIL_EXISTS")
	case errors.Is(err, domainerrors.ErrInvalidCredentials):
		respondError(w, http.StatusUnauthorized, "invalid credentials", "INVALID_CREDENTIALS")
	case errors.Is(err, domainerrors.ErrEmailNotVerified):
		respondError(w, http.StatusForbidden, "email not verified", "EMAIL_NOT_VERIFIED")
	case errors.Is(err, domainerrors.ErrInvalidVerificationToken):
		respondError(w, http.StatusBadRequest, "invalid or expired verification token", "INVALID_VERIFICATION_TOKEN")
	case errors.Is(err, domainerrors.ErrInvalidResetToken):
		respondError(w, http.StatusBadRequest, "invalid or expired reset token", "INVALID_RESET_TOKEN")
	case errors.Is(err, domainerrors.ErrInvalidToken):
		respondError(w, http.StatusUnauthorized, "invalid token", "INVALID_TOKEN")
	case errors.Is(err, domainerrors.ErrTokenExpired):
		respondError(w, http.StatusUnauthorized, "token expired", "TOKEN_EXPIRED")
	case errors.Is(err, domainerrors.ErrTokenRevoked):
		respondError(w, http.StatusUnauthorized, "token revoked", "TOKEN_REVOKED")
	default:
		if errors.Unwrap(err) == nil {
			respondError(w, http.StatusBadRequest, err.Error(), "VALIDATION_ERROR")
			return
		}
		log.Error("internal error",
			zap.Error(err),
			zap.String("request_id", middleware.GetRequestID(r.Context())),
		)
		respondError(w, http.StatusInternalServerError, "internal server error", "INTERNAL_ERROR")
	}
}
