package discovery

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDiscovery(t *testing.T) {
	cfg := &Config{
		Issuer:  "https://sso.example.com",
		BaseURL: "https://sso.example.com",
	}
	h := NewHandler(cfg)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	rec := httptest.NewRecorder()

	h.Discovery(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	var resp discoveryResponse
	err := json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)

	// Required fields (OIDC Discovery 1.0, Section 3)
	assert.Equal(t, "https://sso.example.com", resp.Issuer)
	assert.Equal(t, "https://sso.example.com/api/v1/oauth/authorize", resp.AuthorizationEndpoint)
	assert.Equal(t, "https://sso.example.com/api/v1/oauth/token", resp.TokenEndpoint)
	assert.Equal(t, "https://sso.example.com/.well-known/jwks.json", resp.JwksURI)
	assert.Equal(t, []string{"code"}, resp.ResponseTypesSupported)
	assert.Equal(t, []string{"public"}, resp.SubjectTypesSupported)
	assert.Equal(t, []string{"EdDSA"}, resp.IDTokenSigningAlgValuesSupported)

	// Recommended/optional but important
	assert.Equal(t, "https://sso.example.com/api/v1/oauth/revoke", resp.RevocationEndpoint)
	assert.Equal(t, []string{"authorization_code", "refresh_token"}, resp.GrantTypesSupported)
	assert.Equal(t, []string{"client_secret_basic", "client_secret_post"}, resp.TokenEndpointAuthMethodsSupported)
	assert.Equal(t, []string{"none"}, resp.RevocationEndpointAuthMethods)
	assert.Equal(t, []string{"S256"}, resp.CodeChallengeMethodsSupported)

	// Scopes and claims
	assert.Contains(t, resp.ScopesSupported, "openid")
	assert.Contains(t, resp.ClaimsSupported, "sub")
	assert.Contains(t, resp.ClaimsSupported, "email")
}

func TestDiscovery_DifferentBaseURL(t *testing.T) {
	cfg := &Config{
		Issuer:  "https://auth.production.com",
		BaseURL: "https://auth.production.com",
	}
	h := NewHandler(cfg)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	rec := httptest.NewRecorder()

	h.Discovery(rec, req)

	var resp discoveryResponse
	err := json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)

	// All URLs use the production BaseURL
	assert.Equal(t, "https://auth.production.com", resp.Issuer)
	assert.Equal(t, "https://auth.production.com/api/v1/oauth/authorize", resp.AuthorizationEndpoint)
	assert.Equal(t, "https://auth.production.com/api/v1/oauth/token", resp.TokenEndpoint)
	assert.Equal(t, "https://auth.production.com/api/v1/oauth/revoke", resp.RevocationEndpoint)
	assert.Equal(t, "https://auth.production.com/.well-known/jwks.json", resp.JwksURI)
}

func TestDiscovery_ResponseIsValidJSON(t *testing.T) {
	h := NewHandler(&Config{
		Issuer:  "https://example.com",
		BaseURL: "https://example.com",
	})

	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	rec := httptest.NewRecorder()

	h.Discovery(rec, req)

	// Verify it's valid JSON
	assert.True(t, json.Valid(rec.Body.Bytes()), "response should be valid JSON")
}

func TestDiscovery_Idempotent(t *testing.T) {
	h := NewHandler(&Config{
		Issuer:  "https://example.com",
		BaseURL: "https://example.com",
	})

	// Call twice — responses must be identical
	req1 := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	rec1 := httptest.NewRecorder()
	h.Discovery(rec1, req1)

	req2 := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	rec2 := httptest.NewRecorder()
	h.Discovery(rec2, req2)

	assert.Equal(t, rec1.Body.String(), rec2.Body.String())
}
