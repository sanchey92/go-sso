//go:build e2e

package e2e

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthorize_InvalidClientID(t *testing.T) {
	resp := getWithQuery(t, "/api/v1/oauth/authorize", url.Values{
		"client_id":             {"00000000-0000-0000-0000-000000000000"},
		"redirect_uri":          {"https://example.com/callback"},
		"response_type":         {"code"},
		"scope":                 {"openid"},
		"state":                 {"state"},
		"code_challenge":        {"challenge"},
		"code_challenge_method": {"S256"},
		"user_id":               {"some-user"},
	})
	// Pre-redirect error: invalid client_id → JSON 400 (RFC 6749 §4.1.2.1)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp.Body.Close()
}

func TestAuthorize_MissingClientID(t *testing.T) {
	resp := getWithQuery(t, "/api/v1/oauth/authorize", url.Values{
		"redirect_uri":          {"https://example.com/callback"},
		"response_type":         {"code"},
		"code_challenge":        {"challenge"},
		"code_challenge_method": {"S256"},
		"user_id":               {"some-user"},
	})
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)

	result := decodeJSON[map[string]string](t, resp)
	assert.Equal(t, "INVALID_REQUEST", result["code"])
}

func TestTokenExchange_WrongPKCE(t *testing.T) {
	restoreDB(t)
	flushRedis(t)

	// Setup: full flow до получения code
	userID := registerUser(t, "pkce@example.com", "password123")
	verifyEmail(t)
	_, _ = loginUser(t, "pkce@example.com", "password123")

	redirectURI := "https://app.example.com/callback"
	clientID, clientSecret := createOAuthClient(t, redirectURI)

	_, challenge := generatePKCE(t)

	authResp := getWithQuery(t, "/api/v1/oauth/authorize", url.Values{
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"response_type":         {"code"},
		"scope":                 {"openid"},
		"state":                 {"s"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"user_id":               {userID},
	})
	require.Equal(t, http.StatusFound, authResp.StatusCode)
	authResp.Body.Close()

	location, _ := url.Parse(authResp.Header.Get("Location"))
	code := location.Query().Get("code")
	require.NotEmpty(t, code)

	// Подставляем НЕВЕРНЫЙ code_verifier
	tokenResp := postForm(t, "/api/v1/oauth/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {"wrong-verifier-that-does-not-match"},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	})
	require.Equal(t, http.StatusBadRequest, tokenResp.StatusCode)

	result := decodeJSON[map[string]string](t, tokenResp)
	assert.Equal(t, "invalid_grant", result["error"])
	tokenResp.Body.Close()
}

func TestTokenExchange_CodeReuse(t *testing.T) {
	restoreDB(t)
	flushRedis(t)

	userID := registerUser(t, "reuse@example.com", "password123")
	verifyEmail(t)
	_, _ = loginUser(t, "reuse@example.com", "password123")

	redirectURI := "https://app.example.com/callback"
	clientID, clientSecret := createOAuthClient(t, redirectURI)

	verifier, challenge := generatePKCE(t)

	authResp := getWithQuery(t, "/api/v1/oauth/authorize", url.Values{
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"response_type":         {"code"},
		"scope":                 {"openid"},
		"state":                 {"s"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"user_id":               {userID},
	})
	require.Equal(t, http.StatusFound, authResp.StatusCode)
	authResp.Body.Close()

	location, _ := url.Parse(authResp.Header.Get("Location"))
	code := location.Query().Get("code")

	// Первый exchange — OK
	resp1 := postForm(t, "/api/v1/oauth/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {verifier},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	})
	require.Equal(t, http.StatusOK, resp1.StatusCode)
	resp1.Body.Close()

	// Повторный exchange тем же кодом — FAIL
	// (auth code удаляется из Redis после первого exchange)
	resp2 := postForm(t, "/api/v1/oauth/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {verifier},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	})
	require.Equal(t, http.StatusBadRequest, resp2.StatusCode)

	result := decodeJSON[map[string]string](t, resp2)
	assert.Equal(t, "invalid_grant", result["error"])
}

func TestRevoke_InvalidToken_StillReturns200(t *testing.T) {
	// RFC 7009: revocation endpoint ALWAYS returns 200 OK,
	// even for invalid, expired, or nonexistent tokens.
	revokeResp := postForm(t, "/api/v1/oauth/revoke", url.Values{
		"token": {"completely-invalid-token"},
	})
	require.Equal(t, http.StatusOK, revokeResp.StatusCode)
	revokeResp.Body.Close()
}

func TestRevoke_MissingToken_Returns400(t *testing.T) {
	// RFC 7009: 400 only for malformed requests (missing token param)
	revokeResp := postForm(t, "/api/v1/oauth/revoke", url.Values{})
	require.Equal(t, http.StatusBadRequest, revokeResp.StatusCode)
	revokeResp.Body.Close()
}

func TestRefreshToken_ReplayDetection(t *testing.T) {
	restoreDB(t)
	flushRedis(t)

	registerUser(t, "replay@example.com", "password123")
	verifyEmail(t)
	_, refreshToken := loginUser(t, "replay@example.com", "password123")

	// Первый refresh — OK, получаем новый токен
	resp1 := postJSON(t, "/api/v1/auth/token/refresh", map[string]string{
		"refresh_token": refreshToken,
	})
	require.Equal(t, http.StatusOK, resp1.StatusCode)
	result1 := decodeJSON[map[string]any](t, resp1)
	newRefreshToken := result1["refresh_token"].(string)
	assert.NotEqual(t, refreshToken, newRefreshToken)

	// Повторное использование СТАРОГО refresh token — replay attack!
	// Должен вернуть ошибку (token revoked)
	resp2 := postJSON(t, "/api/v1/auth/token/refresh", map[string]string{
		"refresh_token": refreshToken,
	})
	require.Equal(t, http.StatusUnauthorized, resp2.StatusCode)
	resp2.Body.Close()

	// Новый refresh token тоже должен быть инвалидирован
	// (вся семья revoked при replay detection)
	resp3 := postJSON(t, "/api/v1/auth/token/refresh", map[string]string{
		"refresh_token": newRefreshToken,
	})
	require.Equal(t, http.StatusUnauthorized, resp3.StatusCode)
	resp3.Body.Close()
}
