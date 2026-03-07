package rest

import (
	"errors"
	"net/http"

	"go.uber.org/zap"

	domainerrors "github.com/sanchey92/sso/internal/domain/errors"
)

func handleServiceError(w http.ResponseWriter, r *http.Request, err error, log *zap.Logger) {
	switch {
	case errors.Is(err, domainerrors.ErrEmailAlreadyExists):
		respondError(w, http.StatusConflict, "email already exists", "EMAIL_EXISTS")
	case errors.Is(err, domainerrors.ErrInvalidCredentials):
		respondError(w, http.StatusUnauthorized, "invalid credentials", "INVALID_CREDENTIALS")
	case errors.Is(err, domainerrors.ErrEmailNotVerified):
		respondError(w, http.StatusForbidden, "email not verified", "EMAIL_NOT_VERIFIED")
	case errors.Is(err, domainerrors.ErrInvalidVerificationToken): // NEW
		respondError(w, http.StatusBadRequest, "invalid or expired verification token", "INVALID_VERIFICATION_TOKEN")
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
			zap.String("request_id", GetRequestID(r.Context())),
		)
		respondError(w, http.StatusInternalServerError, "internal server error", "INTERNAL_ERROR")
	}
}
