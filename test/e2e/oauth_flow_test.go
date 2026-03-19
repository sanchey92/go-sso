//go:build e2e

package e2e

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOAuthFlow_HappyPath(t *testing.T) {
	// restoreDB(t) // TODO: fix — closes pool used by server handlers
	flushRedis(t)

	const (
		testEmail    = "oauth@example.com"
		testPassword = "securepassword123"
		redirectURI  = "https://app.example.com/callback"
	)

	// === Шаг 1: Register ===
	userID := registerUser(t, testEmail, testPassword)
	assert.NotEmpty(t, userID)

	// === Шаг 2: Verify Email ===
	// (без верификации Login вернёт 403 ErrEmailNotVerified)
	verifyEmail(t)

	// === Шаг 3: Login ===
	accessToken, refreshToken := loginUser(t, testEmail, testPassword)
	assert.NotEmpty(t, accessToken)
	assert.NotEmpty(t, refreshToken)

	// === Шаг 4: Create OAuth Client ===
	clientID, clientSecret := createOAuthClient(t, redirectURI)
	assert.NotEmpty(t, clientID)
	assert.NotEmpty(t, clientSecret)

	// === Шаг 5: OAuth Authorize (получаем authorization code) ===
	verifier, challenge := generatePKCE(t)

	authResp := getWithQuery(t, "/api/v1/oauth/authorize", url.Values{
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"response_type":         {"code"},
		"scope":                 {"openid profile email"},
		"state":                 {"test-state-123"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"user_id":               {userID},
	})
	require.Equal(t, http.StatusFound, authResp.StatusCode)
	authResp.Body.Close()

	// Извлекаем code из Location header
	location := authResp.Header.Get("Location")
	require.NotEmpty(t, location)

	redirectURL, err := url.Parse(location)
	require.NoError(t, err)

	code := redirectURL.Query().Get("code")
	require.NotEmpty(t, code, "authorization code must be present in redirect")

	state := redirectURL.Query().Get("state")
	assert.Equal(t, "test-state-123", state, "state must be echoed back")

	// === Шаг 6: Exchange Code for Tokens (OAuth Token Endpoint) ===
	tokenResp := postForm(t, "/api/v1/oauth/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {verifier},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	})
	require.Equal(t, http.StatusOK, tokenResp.StatusCode)

	tokenResult := decodeJSON[map[string]any](t, tokenResp)
	oauthAccessToken := tokenResult["access_token"].(string)
	oauthRefreshToken := tokenResult["refresh_token"].(string)
	assert.NotEmpty(t, oauthAccessToken)
	assert.NotEmpty(t, oauthRefreshToken)
	assert.Equal(t, "Bearer", tokenResult["token_type"])
	assert.Greater(t, tokenResult["expires_in"].(float64), float64(0))

	// Проверяем Cache-Control headers (RFC 6749 §5.1)
	assert.Equal(t, "no-store", tokenResp.Header.Get("Cache-Control"))
	assert.Equal(t, "no-cache", tokenResp.Header.Get("Pragma"))

	// === Шаг 7: UserInfo с OAuth access token ===
	req, err := http.NewRequest("POST", baseURL+"/api/v1/oauth/userinfo", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+oauthAccessToken)

	infoResp, err := httpClient.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, infoResp.StatusCode)

	infoResult := decodeJSON[map[string]any](t, infoResp)
	assert.Equal(t, userID, infoResult["sub"])
	assert.Equal(t, testEmail, infoResult["email"])
	assert.Equal(t, true, infoResult["email_verified"])

	// === Шаг 8: Refresh Token (через OAuth endpoint) ===
	refreshResp := postForm(t, "/api/v1/oauth/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {oauthRefreshToken},
	})
	require.Equal(t, http.StatusOK, refreshResp.StatusCode)

	refreshResult := decodeJSON[map[string]any](t, refreshResp)
	newAccessToken := refreshResult["access_token"].(string)
	newRefreshToken := refreshResult["refresh_token"].(string)
	assert.NotEmpty(t, newAccessToken)
	assert.NotEmpty(t, newRefreshToken)
	// Refresh rotation: новый refresh token ОТЛИЧАЕТСЯ от старого
	assert.NotEqual(t, oauthRefreshToken, newRefreshToken)

	// === Шаг 9: Revoke Token (RFC 7009) ===
	revokeResp := postForm(t, "/api/v1/oauth/revoke", url.Values{
		"token": {newRefreshToken},
	})
	require.Equal(t, http.StatusOK, revokeResp.StatusCode)
	revokeResp.Body.Close()

	// Проверяем что revoked token больше не работает
	failRefreshResp := postForm(t, "/api/v1/oauth/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {newRefreshToken},
	})
	assert.NotEqual(t, http.StatusOK, failRefreshResp.StatusCode)
	failRefreshResp.Body.Close()
}
