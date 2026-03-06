package rest

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func newTestServer() *Server {
	return NewServer(&Config{Host: "localhost", Port: 0}, &AuthHandler{}, zap.NewNop())
}

func TestHealthz(t *testing.T) {
	srv := newTestServer()

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.JSONEq(t, `{"status":"ok"}`, rec.Body.String())
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
}

func TestRequestIDHeader(t *testing.T) {
	srv := newTestServer()

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	id := rec.Header().Get("X-Request-ID")
	require.NotEmpty(t, id)

	_, err := uuid.Parse(id)
	assert.NoError(t, err, "X-Request-ID should be valid UUID")
}

func TestPanicRecovery(t *testing.T) {
	srv := newTestServer()

	srv.router.Get("/panic", func(_ http.ResponseWriter, _ *http.Request) {
		panic("test panic")
	})

	req := httptest.NewRequest(http.MethodGet, "/panic", nil)
	rec := httptest.NewRecorder()

	require.NotPanics(t, func() {
		srv.router.ServeHTTP(rec, req)
	})
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestCORSHeaders(t *testing.T) {
	srv := newTestServer()

	req := httptest.NewRequest(http.MethodOptions, "/healthz", nil)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNoContent, rec.Code)
	assert.Equal(t, "*", rec.Header().Get("Access-Control-Allow-Origin"))
	assert.Contains(t, rec.Header().Get("Access-Control-Allow-Methods"), "POST")
	assert.Contains(t, rec.Header().Get("Access-Control-Allow-Headers"), "Authorization")
	assert.Contains(t, rec.Header().Get("Access-Control-Expose-Headers"), "X-Request-ID")
}
