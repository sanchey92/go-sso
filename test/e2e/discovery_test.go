//go:build e2e

package e2e

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOIDCDiscovery(t *testing.T) {
	resp, err := httpClient.Get(baseURL + "/.well-known/openid-configuration")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	result := decodeJSON[map[string]any](t, resp)

	// Обязательные поля OIDC Discovery 1.0
	assert.Equal(t, "test-sso", result["issuer"])
	assert.NotEmpty(t, result["authorization_endpoint"])
	assert.NotEmpty(t, result["token_endpoint"])
	assert.NotEmpty(t, result["jwks_uri"])
	assert.NotEmpty(t, result["userinfo_endpoint"])
	assert.NotEmpty(t, result["revocation_endpoint"])

	// Поддерживаемые значения
	assert.Contains(t, result["response_types_supported"], "code")
	assert.Contains(t, result["grant_types_supported"], "authorization_code")
	assert.Contains(t, result["grant_types_supported"], "refresh_token")
	assert.Contains(t, result["id_token_signing_alg_values_supported"], "EdDSA")
	assert.Contains(t, result["code_challenge_methods_supported"], "S256")
	assert.Contains(t, result["scopes_supported"], "openid")
	assert.Contains(t, result["claims_supported"], "sub")
	assert.Contains(t, result["claims_supported"], "email")
}

func TestJWKS(t *testing.T) {
	resp, err := httpClient.Get(baseURL + "/.well-known/jwks.json")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	assert.Equal(t, "public, max-age=3600", resp.Header.Get("Cache-Control"))

	result := decodeJSON[map[string]any](t, resp)

	// JWKS должен содержать массив keys
	keys, ok := result["keys"].([]any)
	require.True(t, ok, "keys must be an array")
	require.NotEmpty(t, keys, "at least one key must be present")

	// Проверяем структуру первого ключа (EdDSA/Ed25519)
	key := keys[0].(map[string]any)
	assert.Equal(t, "OKP", key["kty"])     // Key Type: Octet Key Pair
	assert.Equal(t, "Ed25519", key["crv"]) // Curve: Ed25519
	assert.Equal(t, "sig", key["use"])     // Use: signature
	assert.Equal(t, "EdDSA", key["alg"])   // Algorithm: EdDSA
	assert.NotEmpty(t, key["kid"])         // Key ID
	assert.NotEmpty(t, key["x"])           // Public key (base64url)
}

func TestHealthz(t *testing.T) {
	resp, err := httpClient.Get(baseURL + "/healthz")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	result := decodeJSON[map[string]string](t, resp)
	assert.Equal(t, "ok", result["status"])
}
