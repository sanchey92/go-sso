//go:build e2e

package e2e

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMagicLink_FullFlow(t *testing.T) {
	restoreDB(t)
	flushRedis(t)

	// 1. Register and verify email
	registerUser(t, "magic@example.com", "password123")
	verifyEmail(t)

	// 2. Request magic link
	resp := postJSON(t, "/api/v1/auth/magic-link/request", map[string]string{
		"email": "magic@example.com",
	})
	require.Equal(t, http.StatusOK, resp.StatusCode)

	msg := decodeJSON[map[string]string](t, resp)
	assert.Contains(t, msg["message"], "if the email exists")

	// 3. Get captured token and verify
	token := getMagicLinkToken(t)

	resp = postJSON(t, "/api/v1/auth/magic-link/verify", map[string]string{
		"token": token,
	})
	require.Equal(t, http.StatusOK, resp.StatusCode)

	tokens := decodeJSON[map[string]any](t, resp)
	assert.NotEmpty(t, tokens["access_token"])
	assert.NotEmpty(t, tokens["refresh_token"])
	assert.Equal(t, "Bearer", tokens["token_type"])

	// 4. Same token again — single-use, should fail
	resp = postJSON(t, "/api/v1/auth/magic-link/verify", map[string]string{
		"token": token,
	})
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	errResult := decodeJSON[map[string]string](t, resp)
	assert.Equal(t, "INVALID_MAGIC_LINK", errResult["code"])
}

func TestMagicLink_AntiEnumeration(t *testing.T) {
	flushRedis(t)

	// Request for non-existent email — must return 200 (no enumeration)
	resp := postJSON(t, "/api/v1/auth/magic-link/request", map[string]string{
		"email": "nonexistent@example.com",
	})
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	msg := decodeJSON[map[string]string](t, resp)
	assert.Contains(t, msg["message"], "if the email exists")
}

func TestMagicLink_InvalidToken(t *testing.T) {
	resp := postJSON(t, "/api/v1/auth/magic-link/verify", map[string]string{
		"token": "completely-bogus-token-that-does-not-exist",
	})
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	errResult := decodeJSON[map[string]string](t, resp)
	assert.Equal(t, "INVALID_MAGIC_LINK", errResult["code"])
}
