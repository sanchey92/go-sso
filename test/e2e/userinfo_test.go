//go:build e2e

package e2e

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUserInfo_ValidToken(t *testing.T) {
	restoreDB(t)
	flushRedis(t)

	// Setup: register + verify + login
	registerUser(t, "info@example.com", "password123")
	verifyEmail(t)
	accessToken, _ := loginUser(t, "info@example.com", "password123")

	// Act: UserInfo с валидным токеном
	req, err := http.NewRequest("POST", baseURL+"/api/v1/oauth/userinfo", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := httpClient.Do(req)
	require.NoError(t, err)

	// Assert
	require.Equal(t, http.StatusOK, resp.StatusCode)

	result := decodeJSON[map[string]any](t, resp)
	assert.Equal(t, "info@example.com", result["email"])
	assert.Equal(t, true, result["email_verified"])
	assert.NotEmpty(t, result["sub"])
}

func TestUserInfo_MissingToken(t *testing.T) {
	// Без Authorization header
	req, err := http.NewRequest("POST", baseURL+"/api/v1/oauth/userinfo", nil)
	require.NoError(t, err)

	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// RFC 6750: WWW-Authenticate header должен содержать realm
	wwwAuth := resp.Header.Get("WWW-Authenticate")
	assert.Contains(t, wwwAuth, `Bearer realm="sso"`)
}

func TestUserInfo_InvalidToken(t *testing.T) {
	req, err := http.NewRequest("POST", baseURL+"/api/v1/oauth/userinfo", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer invalid.jwt.token")

	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	wwwAuth := resp.Header.Get("WWW-Authenticate")
	assert.Contains(t, wwwAuth, "invalid_token")
}

func TestUserInfo_WrongScheme(t *testing.T) {
	// "bearer" (lowercase) — не должен работать (case-sensitive prefix)
	req, err := http.NewRequest("POST", baseURL+"/api/v1/oauth/userinfo", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "bearer some-token")

	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}
