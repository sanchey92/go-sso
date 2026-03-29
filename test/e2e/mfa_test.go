//go:build e2e

package e2e

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupMFAUser registers a user, verifies email, logs in, sets up TOTP and verifies setup.
// Returns access token, TOTP secret, and recovery codes.
func setupMFAUser(t *testing.T, email, password string) (accessToken, secret string, recoveryCodes []string) {
	t.Helper()

	registerUser(t, email, password)
	verifyEmail(t)

	accessToken, _ = loginUser(t, email, password)

	// Setup TOTP
	resp := postJSONWithAuth(t, "/api/v1/auth/mfa/totp/setup", nil, accessToken)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	setupResult := decodeJSON[map[string]string](t, resp)
	secretURI := setupResult["secret_uri"]
	require.NotEmpty(t, secretURI)

	// Parse secret from otpauth:// URI
	key, err := otp.NewKeyFromURL(secretURI)
	require.NoError(t, err)
	secret = key.Secret()

	// Generate valid TOTP code
	code, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)

	// Verify setup
	resp = postJSONWithAuth(t, "/api/v1/auth/mfa/totp/verify-setup", map[string]string{
		"code": code,
	}, accessToken)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	verifyResult := decodeJSON[map[string]any](t, resp)
	rawCodes, ok := verifyResult["recovery_codes"].([]any)
	require.True(t, ok)
	require.Len(t, rawCodes, 10)

	recoveryCodes = make([]string, len(rawCodes))
	for i, c := range rawCodes {
		recoveryCodes[i] = c.(string)
	}

	return accessToken, secret, recoveryCodes
}

// generateTOTP generates a valid TOTP code from the secret.
func generateTOTP(t *testing.T, secret string) string {
	t.Helper()
	code, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)
	return code
}

func TestMFA_TOTPFullFlow(t *testing.T) {
	restoreDB(t)
	flushRedis(t)

	// 1. Setup MFA user
	_, secret, recoveryCodes := setupMFAUser(t, "mfa@example.com", "password123")
	require.Len(t, recoveryCodes, 10)

	// 2. Login again — now MFA is required
	_, _, mfaToken, mfaRequired := loginUserMFA(t, "mfa@example.com", "password123")
	require.True(t, mfaRequired)
	require.NotEmpty(t, mfaToken)

	// 3. Complete MFA with TOTP code
	code := generateTOTP(t, secret)
	resp := postJSON(t, "/api/v1/auth/mfa/totp/verify", map[string]string{
		"mfa_token": mfaToken,
		"code":      code,
	})
	require.Equal(t, http.StatusOK, resp.StatusCode)

	tokens := decodeJSON[map[string]any](t, resp)
	assert.NotEmpty(t, tokens["access_token"])
	assert.NotEmpty(t, tokens["refresh_token"])
	assert.Equal(t, "Bearer", tokens["token_type"])
}

func TestMFA_RecoveryFlow(t *testing.T) {
	restoreDB(t)
	flushRedis(t)

	_, _, recoveryCodes := setupMFAUser(t, "recovery@example.com", "password123")

	// 1. Login — MFA required
	_, _, mfaToken, mfaRequired := loginUserMFA(t, "recovery@example.com", "password123")
	require.True(t, mfaRequired)

	// 2. Complete MFA with recovery code
	resp := postJSON(t, "/api/v1/auth/mfa/recovery/verify", map[string]string{
		"mfa_token": mfaToken,
		"code":      recoveryCodes[0],
	})
	require.Equal(t, http.StatusOK, resp.StatusCode)

	tokens := decodeJSON[map[string]any](t, resp)
	assert.NotEmpty(t, tokens["access_token"])
	assert.NotEmpty(t, tokens["refresh_token"])

	// 3. Login again — try same recovery code (already used)
	_, _, mfaToken, _ = loginUserMFA(t, "recovery@example.com", "password123")

	resp = postJSON(t, "/api/v1/auth/mfa/recovery/verify", map[string]string{
		"mfa_token": mfaToken,
		"code":      recoveryCodes[0],
	})
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	errResult := decodeJSON[map[string]string](t, resp)
	assert.Equal(t, "INVALID_RECOVERY_CODE", errResult["code"])
}

func TestMFA_DisableFlow(t *testing.T) {
	restoreDB(t)
	flushRedis(t)

	_, secret, _ := setupMFAUser(t, "disable@example.com", "password123")

	// 1. Login — MFA required
	_, _, mfaToken, mfaRequired := loginUserMFA(t, "disable@example.com", "password123")
	require.True(t, mfaRequired)

	// 2. Complete MFA login to get access token
	code := generateTOTP(t, secret)
	resp := postJSON(t, "/api/v1/auth/mfa/totp/verify", map[string]string{
		"mfa_token": mfaToken,
		"code":      code,
	})
	require.Equal(t, http.StatusOK, resp.StatusCode)

	tokens := decodeJSON[map[string]any](t, resp)
	accessToken := tokens["access_token"].(string)

	// 3. Disable MFA with TOTP code
	disableCode := generateTOTP(t, secret)
	resp = deleteJSONWithAuth(t, "/api/v1/auth/mfa/totp", map[string]string{
		"code": disableCode,
	}, accessToken)
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	resp.Body.Close()

	// 4. Login again — no MFA required
	at, rt, _, mfaRequired := loginUserMFA(t, "disable@example.com", "password123")
	assert.False(t, mfaRequired)
	assert.NotEmpty(t, at)
	assert.NotEmpty(t, rt)
}

func TestMFA_ErrorCases(t *testing.T) {
	t.Run("wrong TOTP code on verify", func(t *testing.T) {
		restoreDB(t)
		flushRedis(t)

		setupMFAUser(t, "err1@example.com", "password123")

		_, _, mfaToken, _ := loginUserMFA(t, "err1@example.com", "password123")

		resp := postJSON(t, "/api/v1/auth/mfa/totp/verify", map[string]string{
			"mfa_token": mfaToken,
			"code":      "000000",
		})
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

		errResult := decodeJSON[map[string]string](t, resp)
		assert.Equal(t, "INVALID_TOTP_CODE", errResult["code"])
	})

	t.Run("setup when MFA already enabled", func(t *testing.T) {
		restoreDB(t)
		flushRedis(t)

		accessToken, _, _ := setupMFAUser(t, "err2@example.com", "password123")

		resp := postJSONWithAuth(t, "/api/v1/auth/mfa/totp/setup", nil, accessToken)
		assert.Equal(t, http.StatusConflict, resp.StatusCode)

		errResult := decodeJSON[map[string]string](t, resp)
		assert.Equal(t, "MFA_ALREADY_ENABLED", errResult["code"])
	})

	t.Run("verify-setup with wrong code", func(t *testing.T) {
		restoreDB(t)
		flushRedis(t)

		registerUser(t, "err3@example.com", "password123")
		verifyEmail(t)
		accessToken, _ := loginUser(t, "err3@example.com", "password123")

		// Setup TOTP (but don't verify with correct code)
		resp := postJSONWithAuth(t, "/api/v1/auth/mfa/totp/setup", nil, accessToken)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		resp.Body.Close()

		// Try verify-setup with wrong code
		resp = postJSONWithAuth(t, "/api/v1/auth/mfa/totp/verify-setup", map[string]string{
			"code": "000000",
		}, accessToken)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

		errResult := decodeJSON[map[string]string](t, resp)
		assert.Equal(t, "INVALID_TOTP_CODE", errResult["code"])
	})

	t.Run("TOTP verify without mfa_token", func(t *testing.T) {
		resp := postJSON(t, "/api/v1/auth/mfa/totp/verify", map[string]string{
			"mfa_token": "",
			"code":      "123456",
		})

		// Empty mfa_token will fail validation
		assert.NotEqual(t, http.StatusOK, resp.StatusCode)
		resp.Body.Close()
	})
}

// TestMFA_TOTPVerifyWithoutSetup verifies that TOTP verify fails gracefully
// when the user has no MFA configured.
func TestMFA_TOTPVerifyWithoutSetup(t *testing.T) {
	restoreDB(t)
	flushRedis(t)

	registerUser(t, "nomfa@example.com", "password123")
	verifyEmail(t)

	// Login returns tokens directly (no MFA)
	at, rt, _, mfaRequired := loginUserMFA(t, "nomfa@example.com", "password123")
	assert.False(t, mfaRequired)
	assert.NotEmpty(t, at)
	assert.NotEmpty(t, rt)

	// Attempting to disable MFA when not enabled
	resp := deleteJSONWithAuth(t, "/api/v1/auth/mfa/totp", map[string]string{
		"code": "123456",
	}, at)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	errResult := decodeJSON[map[string]string](t, resp)
	assert.Equal(t, "MFA_NOT_ENABLED", errResult["code"])
}

// urlSetup is used by setup to return the secret_uri. We need to verify the URL
// format is a valid otpauth URI.
func TestMFA_SetupReturnsValidOTPAuthURI(t *testing.T) {
	restoreDB(t)
	flushRedis(t)

	registerUser(t, "uri@example.com", "password123")
	verifyEmail(t)
	accessToken, _ := loginUser(t, "uri@example.com", "password123")

	resp := postJSONWithAuth(t, "/api/v1/auth/mfa/totp/setup", nil, accessToken)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	result := decodeJSON[map[string]string](t, resp)
	secretURI := result["secret_uri"]

	u, err := url.Parse(secretURI)
	require.NoError(t, err)
	assert.Equal(t, "otpauth", u.Scheme)
	assert.Equal(t, "totp", u.Host)
}
