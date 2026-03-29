package mfa

import (
	"net/http"

	"github.com/sanchey92/sso/internal/adapter/driving/rest/httputil"
)

type setupResponse struct {
	SecretURI string `json:"secret_uri"`
}

type codeRequest struct {
	Code string `json:"code"`
}

type verifySetupResponse struct {
	RecoveryCodes []string `json:"recovery_codes"`
}

func (h *Handler) Setup(w http.ResponseWriter, r *http.Request) {
	userID, ok := h.extractUserID(w, r)
	if !ok {
		return
	}

	uri, err := h.totpSvc.SetupTOTP(r.Context(), userID)
	if err != nil {
		h.handleError(w, r, err)
		return
	}
	httputil.RespondJSON(w, http.StatusOK, &setupResponse{
		SecretURI: uri,
	})
}

func (h *Handler) VerifySetup(w http.ResponseWriter, r *http.Request) {
	userID, ok := h.extractUserID(w, r)
	if !ok {
		return
	}
	var req codeRequest
	if err := httputil.DecodeJSON(w, r, &req); err != nil {
		httputil.RespondError(w, http.StatusBadRequest, "invalid request body", "INVALID_REQUEST")
		return
	}
	codes, err := h.totpSvc.VerifySetup(r.Context(), userID, req.Code)
	if err != nil {
		h.handleError(w, r, err)
		return
	}

	httputil.RespondJSON(w, http.StatusOK, &verifySetupResponse{RecoveryCodes: codes})
}

func (h *Handler) Disable(w http.ResponseWriter, r *http.Request) {
	userID, ok := h.extractUserID(w, r)
	if !ok {
		return
	}

	var req codeRequest
	if err := httputil.DecodeJSON(w, r, &req); err != nil {
		httputil.RespondError(w, http.StatusBadRequest, "invalid request body", "INVALID_REQUEST")
		return
	}

	if err := h.totpSvc.DisableTOTP(r.Context(), userID, req.Code); err != nil {
		h.handleError(w, r, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
