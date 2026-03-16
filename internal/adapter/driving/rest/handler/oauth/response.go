package oauth

import (
	"net/http"

	"github.com/sanchey92/sso/internal/adapter/driving/rest/handler/httputil"
	"github.com/sanchey92/sso/internal/domain/model"
)

// oauthTokenResponse — RFC 6749 Section 5.1
type oauthTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

// oauthErrorResponse — RFC 6749 Section 5.2
type oauthErrorResponse struct {
	Error       string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

func respondOAuthError(w http.ResponseWriter, status int, errorCode, description string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	httputil.RespondJSON(w, status, oauthErrorResponse{
		Error:       errorCode,
		Description: description,
	})
}

func respondOAuthToken(w http.ResponseWriter, pair *model.TokenPair) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	httputil.RespondJSON(w, http.StatusOK, oauthTokenResponse{
		AccessToken:  pair.AccessToken,
		TokenType:    "Bearer",
		ExpiresIn:    pair.ExpiresIn,
		RefreshToken: pair.RefreshToken,
	})
}
