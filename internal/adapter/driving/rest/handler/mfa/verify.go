package mfa

import (
	"context"
	"errors"
	"net/http"

	"github.com/sanchey92/sso/internal/adapter/driving/rest/handler/httputil"
	domainerrors "github.com/sanchey92/sso/internal/domain/errors"
	"github.com/sanchey92/sso/internal/domain/model"
)

type mfaVerifyRequest struct {
	MFAToken string `json:"mfa_token"`
	Code     string `json:"code"`
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	TokenType    string `json:"token_type"`
}

func (h *Handler) VerifyTOTP(w http.ResponseWriter, r *http.Request) {
	h.completeVerify(w, r, h.completer.CompleteMFALogin)
}

func (h *Handler) VerifyRecovery(w http.ResponseWriter, r *http.Request) {
	h.completeVerify(w, r, h.completer.CompleteMFARecovery)
}

type completeFn func(ctx context.Context, token, code string) (*model.TokenPair, error)

func (h *Handler) completeVerify(w http.ResponseWriter, r *http.Request, fn completeFn) {
	var req mfaVerifyRequest
	if err := httputil.DecodeJSON(w, r, &req); err != nil {
		httputil.RespondError(w, http.StatusBadRequest, "invalid request body", "INVALID_REQUEST")
		return
	}

	pair, err := fn(r.Context(), req.MFAToken, req.Code)
	if err != nil {
		h.handleVerifyError(w, r, err)
		return
	}

	httputil.RespondJSON(w, http.StatusOK, &tokenResponse{
		AccessToken:  pair.AccessToken,
		RefreshToken: pair.RefreshToken,
		ExpiresIn:    pair.ExpiresIn,
		TokenType:    "Bearer",
	})
}

func (h *Handler) handleVerifyError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, domainerrors.ErrInvalidTOTPCode):
		httputil.RespondError(w, http.StatusUnauthorized, "invalid totp code", "INVALID_TOTP_CODE")
	case errors.Is(err, domainerrors.ErrRecoveryCodeNotFound):
		httputil.RespondError(w, http.StatusUnauthorized, "invalid recovery code", "INVALID_RECOVERY_CODE")
	default:
		h.handleError(w, r, err)
	}
}
