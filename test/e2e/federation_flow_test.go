//go:build e2e

package e2e

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFederation_AutoProvisioning(t *testing.T) {
	restoreDB(t)
	flushRedis(t)

	setMockGoogleUser("google-123", "federated@gmail.com", "Fed User", "https://photo.url/pic.jpg", true)

	// Authorize → redirect to Google
	state := federationAuthorize(t, "google")

	// Callback → auto-provision user → tokens
	accessToken, refreshToken := federationCallback(t, "google", "mock-auth-code", state)
	assert.NotEmpty(t, accessToken)
	assert.NotEmpty(t, refreshToken)

	// Verify auto-provisioned user via UserInfo
	info := getUserInfo(t, accessToken)
	assert.Equal(t, "federated@gmail.com", info["email"])
	assert.Equal(t, true, info["email_verified"])
	assert.NotEmpty(t, info["sub"])
}

func TestFederation_AccountLinking(t *testing.T) {
	restoreDB(t)
	flushRedis(t)

	const (
		email    = "linking@gmail.com"
		password = "securepassword123"
	)

	// Register user with same email as the one Google will return
	userID := registerUser(t, email, password)
	verifyEmail(t)

	// Federation with same email → should link to existing account
	setMockGoogleUser("google-link-456", email, "Linked User", "", true)

	state := federationAuthorize(t, "google")
	accessToken, _ := federationCallback(t, "google", "mock-code", state)

	// UserInfo should return the same user (linked, not a new one)
	info := getUserInfo(t, accessToken)
	assert.Equal(t, userID, info["sub"])
	assert.Equal(t, email, info["email"])
}

func TestFederation_RepeatLogin(t *testing.T) {
	restoreDB(t)
	flushRedis(t)

	setMockGoogleUser("google-repeat-789", "repeat@gmail.com", "Repeat User", "", true)

	// First login → auto-provision
	state1 := federationAuthorize(t, "google")
	accessToken1, _ := federationCallback(t, "google", "mock-code", state1)
	info1 := getUserInfo(t, accessToken1)

	// Second login → same user, new tokens
	state2 := federationAuthorize(t, "google")
	accessToken2, _ := federationCallback(t, "google", "mock-code", state2)
	info2 := getUserInfo(t, accessToken2)

	assert.Equal(t, info1["sub"], info2["sub"])
	assert.Equal(t, info1["email"], info2["email"])
}

func TestFederation_UnknownProvider(t *testing.T) {
	resp, err := httpClient.Get(baseURL + "/api/v1/federation/facebook/authorize")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusNotFound, resp.StatusCode)

	result := decodeJSON[map[string]string](t, resp)
	assert.Equal(t, "PROVIDER_NOT_FOUND", result["code"])
}

func TestFederation_InvalidState(t *testing.T) {
	flushRedis(t)

	resp := getWithQuery(t, "/api/v1/federation/google/callback", url.Values{
		"code":  {"mock-code"},
		"state": {"invalid-state-that-does-not-exist"},
	})
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	result := decodeJSON[map[string]string](t, resp)
	assert.Equal(t, "INVALID_STATE", result["code"])
}

func TestFederation_MissingCode(t *testing.T) {
	resp := getWithQuery(t, "/api/v1/federation/google/callback", url.Values{
		"state": {"some-state"},
	})
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	result := decodeJSON[map[string]string](t, resp)
	assert.Equal(t, "INVALID_REQUEST", result["code"])
}

func TestFederation_MissingState(t *testing.T) {
	resp := getWithQuery(t, "/api/v1/federation/google/callback", url.Values{
		"code": {"mock-code"},
	})
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	result := decodeJSON[map[string]string](t, resp)
	assert.Equal(t, "INVALID_REQUEST", result["code"])
}

func TestFederation_EmailNotVerified(t *testing.T) {
	restoreDB(t)
	flushRedis(t)

	setMockGoogleUser("google-unverified", "unverified@gmail.com", "Unverified", "", false)

	state := federationAuthorize(t, "google")

	resp := getWithQuery(t, "/api/v1/federation/google/callback", url.Values{
		"code":  {"mock-code"},
		"state": {state},
	})
	defer resp.Body.Close()

	assert.Equal(t, http.StatusForbidden, resp.StatusCode)

	result := decodeJSON[map[string]string](t, resp)
	assert.Equal(t, "EMAIL_NOT_VERIFIED", result["code"])
}

func TestFederation_ProviderError(t *testing.T) {
	resp := getWithQuery(t, "/api/v1/federation/google/callback", url.Values{
		"error":             {"access_denied"},
		"error_description": {"user denied access"},
	})
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	result := decodeJSON[map[string]string](t, resp)
	assert.Equal(t, "access_denied", result["code"])
}
