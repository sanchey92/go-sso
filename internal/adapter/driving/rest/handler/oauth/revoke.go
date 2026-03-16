package oauth

import (
	"net/http"

	"go.uber.org/zap"

	"github.com/sanchey92/sso/internal/adapter/driving/rest/middleware"
)

// Revoke implements RFC 7009 — OAuth 2.0 Token Revocation.
//
// Content-Type: application/x-www-form-urlencoded
// Parameters:
//   - token (REQUIRED) — the token to revoke
//   - token_type_hint (OPTIONAL) — "refresh_token" or "access_token"
//
// Response: ALWAYS 200 OK (even for invalid/expired/unknown tokens).
// Errors (non-200) only for malformed requests.
func (h *Handler) Revoke(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		respondOAuthError(w, http.StatusBadRequest, "invalid_request", "malformed request body")
		return
	}

	token := r.FormValue("token")
	if token == "" {
		respondOAuthError(w, http.StatusBadRequest, "invalid_request", "token is required")
		return
	}

	if err := h.revoker.RevokeToken(r.Context(), token); err != nil {
		h.log.Warn("token revocation failed",
			zap.Error(err),
			zap.String("request_id", middleware.GetRequestID(r.Context())),
		)
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
}
