package rest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sanchey92/sso/internal/adapter/driving/rest/handler/auth"
	"github.com/sanchey92/sso/internal/adapter/driving/rest/handler/client"
	"github.com/sanchey92/sso/internal/adapter/driving/rest/handler/oauth"
	"github.com/sanchey92/sso/internal/adapter/driving/rest/handler/token"
	"github.com/sanchey92/sso/internal/adapter/driving/rest/handler/user"
	"github.com/sanchey92/sso/internal/adapter/driving/rest/middleware"
	"github.com/sanchey92/sso/pkg/metrics"
)

func noopMiddleware(next http.Handler) http.Handler { return next }

func blockingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(http.StatusTooManyRequests)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error": "too many requests",
			"code":  "RATE_LIMITED",
		})
	})
}

var testCORSConfig = middleware.CORSConfig{
	AllowOrigins:  "*",
	AllowMethods:  "GET, POST, PUT, DELETE, OPTIONS",
	AllowHeaders:  "Content-Type, Authorization, X-Request-ID",
	ExposeHeaders: "X-Request-ID",
	MaxAge:        "86400",
}

var testHandlers = Handlers{
	User:   &user.Handler{},
	Auth:   &auth.Handler{},
	Token:  &token.Handler{},
	Client: &client.Handler{},
	OAuth:  &oauth.Handler{},
}

func newTestServer() *Server {
	return NewServer(
		&Config{Host: "localhost", Port: 0},
		testHandlers,
		metrics.NewTest(),
		noopMiddleware,
		noopMiddleware,
		noopMiddleware,
		testCORSConfig,
		zap.NewNop(),
	)
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

func TestLoginRateLimitApplied(t *testing.T) {
	srv := NewServer(
		&Config{Host: "localhost", Port: 0},
		testHandlers,
		metrics.NewTest(),
		blockingMiddleware,
		noopMiddleware,
		noopMiddleware,
		testCORSConfig,
		zap.NewNop(),
	)

	body := `{"email":"test@example.com","password":"password123"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusTooManyRequests, rec.Code)
	assert.Equal(t, "60", rec.Header().Get("Retry-After"))
	assert.Contains(t, rec.Body.String(), "RATE_LIMITED")
}

func TestLoginRateLimitNotAffectOtherRoutes(t *testing.T) {
	srv := NewServer(
		&Config{Host: "localhost", Port: 0},
		testHandlers,
		metrics.NewTest(),
		blockingMiddleware,
		noopMiddleware,
		noopMiddleware,
		testCORSConfig,
		zap.NewNop(),
	)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}
