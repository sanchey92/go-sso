package jwks

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestJWKS_Success(t *testing.T) {
	jwksJSON := `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"abc123","use":"sig","alg":"EdDSA","x":"dGVzdC1rZXk"}]}`

	h := NewHandler(func() ([]byte, error) {
		return []byte(jwksJSON), nil
	}, zap.NewNop())

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rec := httptest.NewRecorder()

	h.JWKS(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	assert.Equal(t, "public, max-age=3600", rec.Header().Get("Cache-Control"))
	assert.JSONEq(t, jwksJSON, rec.Body.String())
}

func TestJWKS_ProviderError(t *testing.T) {
	h := NewHandler(func() ([]byte, error) {
		return nil, errors.New("marshal failed")
	}, zap.NewNop())

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rec := httptest.NewRecorder()

	h.JWKS(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Empty(t, rec.Header().Get("Content-Type"))
}

func TestJWKS_EmptyKeys(t *testing.T) {
	h := NewHandler(func() ([]byte, error) {
		return []byte(`{"keys":[]}`), nil
	}, zap.NewNop())

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rec := httptest.NewRecorder()

	h.JWKS(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.JSONEq(t, `{"keys":[]}`, rec.Body.String())
}

func TestJWKS_ReflectsRotation(t *testing.T) {
	callCount := 0
	responses := []string{
		`{"keys":[{"kty":"OKP","kid":"key-1"}]}`,
		`{"keys":[{"kty":"OKP","kid":"key-1"},{"kty":"OKP","kid":"key-2"}]}`,
	}

	h := NewHandler(func() ([]byte, error) {
		resp := responses[callCount]
		callCount++
		return []byte(resp), nil
	}, zap.NewNop())

	// First request — one key
	req1 := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rec1 := httptest.NewRecorder()
	h.JWKS(rec1, req1)

	require.Equal(t, http.StatusOK, rec1.Code)
	assert.JSONEq(t, responses[0], rec1.Body.String())

	// Second request after "rotation" — two keys
	req2 := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rec2 := httptest.NewRecorder()
	h.JWKS(rec2, req2)

	require.Equal(t, http.StatusOK, rec2.Code)
	assert.JSONEq(t, responses[1], rec2.Body.String())
}
