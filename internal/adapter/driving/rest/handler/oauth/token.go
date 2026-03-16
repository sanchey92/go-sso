package oauth

import (
	"errors"
	"net/http"

	"go.uber.org/zap"

	"github.com/sanchey92/sso/internal/adapter/driving/rest/middleware"
	domainerrors "github.com/sanchey92/sso/internal/domain/errors"
	"github.com/sanchey92/sso/internal/domain/model"
)

func (h *Handler) Token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		respondOAuthError(w, http.StatusBadRequest, "invalid_request", "malformed request body")
		return
	}

	grantType := r.FormValue("grant_type")

	switch grantType {
	case "authorization_code":
		h.handleAuthorizationCodeGrant(w, r)
	case "refresh_token":
		h.handleRefreshTokenGrant(w, r)
	default:
		respondOAuthError(w, http.StatusBadRequest, "unsupported_grant_type",
			"grant_type must be authorization_code or refresh_token")
	}
}

func extractClientCredentials(r *http.Request) (clientID, clientSecret string) {
	// RFC 6749 §2.3.1: HTTP Basic Authentication имеет приоритет
	if id, secret, ok := r.BasicAuth(); ok {
		return id, secret
	}
	return r.FormValue("client_id"), r.FormValue("client_secret")
}

func (h *Handler) handleAuthorizationCodeGrant(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")
	if code == "" {
		respondOAuthError(w, http.StatusBadRequest, "invalid request", "code is required")
		return
	}

	redirectURI := r.FormValue("redirect_uri")
	if redirectURI == "" {
		respondOAuthError(w, http.StatusBadRequest, "invalid request", "redirect_uri is required")
		return
	}

	codeVerifier := r.FormValue("code_verifier")
	if codeVerifier == "" {
		respondOAuthError(w, http.StatusBadRequest, "invalid request", "code verifier is required")
		return
	}

	clientID, clientSecret := extractClientCredentials(r)
	if clientID == "" {
		respondOAuthError(w, http.StatusBadRequest, "invalid request", "client_id is required")
		return
	}

	pair, err := h.exchanger.ExchangeCode(r.Context(), &model.CodeExchangeRequest{
		Code:         code,
		RedirectURI:  redirectURI,
		CodeVerifier: codeVerifier,
		ClientID:     clientID,
		ClientSecret: clientSecret,
	})
	if err != nil {
		h.handleTokenError(w, r, err)
		return
	}
	respondOAuthToken(w, pair)
}

func (h *Handler) handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request) {
	refreshToken := r.FormValue("refresh_token")
	if refreshToken == "" {
		respondOAuthError(w, http.StatusBadRequest, "invalid_request", "refresh_token is required")
		return
	}

	pair, err := h.refresher.RefreshTokens(r.Context(), refreshToken)
	if err != nil {
		h.handleTokenError(w, r, err)
		return
	}
	respondOAuthToken(w, pair)
}

func (h *Handler) handleTokenError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, domainerrors.ErrInvalidAuthorizationCode):
		respondOAuthError(w, http.StatusBadRequest, "invalid_grant",
			"authorization code is invalid, expired, or already used")
	case errors.Is(err, domainerrors.ErrInvalidCredentials):
		respondOAuthError(w, http.StatusUnauthorized, "invalid_client",
			"client authentication failed")
	case errors.Is(err, domainerrors.ErrOAuthClientNotFound):
		respondOAuthError(w, http.StatusUnauthorized, "invalid_client",
			"client not found")
	case errors.Is(err, domainerrors.ErrTokenExpired):
		respondOAuthError(w, http.StatusBadRequest, "invalid_grant",
			"refresh token has expired")
	case errors.Is(err, domainerrors.ErrTokenRevoked):
		respondOAuthError(w, http.StatusBadRequest, "invalid_grant",
			"refresh token has been revoked")
	case errors.Is(err, domainerrors.ErrInvalidToken):
		respondOAuthError(w, http.StatusBadRequest, "invalid_grant",
			"invalid refresh token")
	default:
		h.log.Error("token endpoint error",
			zap.Error(err),
			zap.String("request_id", middleware.GetRequestID(r.Context())),
		)
		respondOAuthError(w, http.StatusInternalServerError, "server_error",
			"internal server error")
	}
}
