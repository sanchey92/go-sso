//go:build e2e

package e2e

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLogin_InvalidPassword(t *testing.T) {
	restoreDB(t)
	flushRedis(t)

	registerUser(t, "wrong@example.com", "password123")
	verifyEmail(t)

	resp := postJSON(t, "/api/v1/auth/login", map[string]string{
		"email":    "wrong@example.com",
		"password": "wrongpassword",
	})
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	result := decodeJSON[map[string]string](t, resp)
	assert.Equal(t, "INVALID_CREDENTIALS", result["code"])
	resp.Body.Close()
}

func TestLogin_EmailNotVerified(t *testing.T) {
	restoreDB(t)
	flushRedis(t)

	registerUser(t, "unverified@example.com", "password123")
	// Намеренно НЕ верифицируем email

	resp := postJSON(t, "/api/v1/auth/login", map[string]string{
		"email":    "unverified@example.com",
		"password": "password123",
	})
	require.Equal(t, http.StatusForbidden, resp.StatusCode)

	result := decodeJSON[map[string]string](t, resp)
	assert.Equal(t, "EMAIL_NOT_VERIFIED", result["code"])
	resp.Body.Close()
}

func TestRegister_DuplicateEmail(t *testing.T) {
	restoreDB(t)
	flushRedis(t)

	registerUser(t, "dup@example.com", "password123")

	// Повторная регистрация с тем же email
	resp := postJSON(t, "/api/v1/auth/register", map[string]string{
		"email":    "dup@example.com",
		"password": "password456",
	})
	require.Equal(t, http.StatusConflict, resp.StatusCode)

	result := decodeJSON[map[string]string](t, resp)
	assert.Equal(t, "EMAIL_EXISTS", result["code"])
	resp.Body.Close()
}
