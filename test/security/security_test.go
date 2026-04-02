//go:build security

package security_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sanchey92/sso/internal/adapter/driving/rest"
	"github.com/sanchey92/sso/internal/adapter/driving/rest/handler/auth"
	"github.com/sanchey92/sso/internal/adapter/driving/rest/handler/client"
	"github.com/sanchey92/sso/internal/adapter/driving/rest/handler/health"
	"github.com/sanchey92/sso/internal/adapter/driving/rest/handler/oauth"
	"github.com/sanchey92/sso/internal/adapter/driving/rest/handler/token"
	"github.com/sanchey92/sso/internal/adapter/driving/rest/handler/user"
	"github.com/sanchey92/sso/internal/adapter/driving/rest/middleware"
	"github.com/sanchey92/sso/pkg/metrics"
)

type mockPingChecker struct{}

func (m *mockPingChecker) Ping(_ context.Context) error { return nil }

func newSecurityTestServer() *rest.Server {
	noopRL := func(next http.Handler) http.Handler { return next }
	return rest.NewServer(
		&rest.Config{Host: "localhost", Port: 0, MetricsPort: 0},
		rest.Handlers{
			User:   &user.Handler{},
			Auth:   &auth.Handler{},
			Token:  &token.Handler{},
			Client: &client.Handler{},
			OAuth:  &oauth.Handler{},
			Health: health.NewHandler(&mockPingChecker{}, &mockPingChecker{}),
		},
		metrics.NewTest(),
		noopRL, noopRL, noopRL,
		middleware.CORSConfig{AllowOrigins: "*", AllowMethods: "GET,POST", AllowHeaders: "Content-Type", ExposeHeaders: "X-Request-ID", MaxAge: "86400"},
		middleware.HSTSConfig{Enabled: true, MaxAge: 31536000},
		zap.NewNop(),
	)
}

func TestSecurityHeaders_Present(t *testing.T) {
	srv := newSecurityTestServer()

	endpoints := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/healthz"},
		{http.MethodGet, "/readyz"},
	}

	for _, ep := range endpoints {
		t.Run(ep.method+" "+ep.path, func(t *testing.T) {
			req := httptest.NewRequest(ep.method, ep.path, nil)
			rec := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rec, req)

			h := rec.Header()
			assert.Equal(t, "nosniff", h.Get("X-Content-Type-Options"))
			assert.Equal(t, "DENY", h.Get("X-Frame-Options"))
			assert.Equal(t, "0", h.Get("X-XSS-Protection"))
			assert.Equal(t, "strict-origin-when-cross-origin", h.Get("Referrer-Policy"))
			assert.Equal(t, "no-store", h.Get("Cache-Control"))
			assert.Equal(t, "default-src 'none'; frame-ancestors 'none'", h.Get("Content-Security-Policy"))
			assert.Equal(t, "max-age=31536000; includeSubDomains", h.Get("Strict-Transport-Security"))
		})
	}
}

func TestSecurityHeaders_HSTS_Disabled(t *testing.T) {
	noopRL := func(next http.Handler) http.Handler { return next }
	srv := rest.NewServer(
		&rest.Config{Host: "localhost", Port: 0, MetricsPort: 0},
		rest.Handlers{
			User:   &user.Handler{},
			Auth:   &auth.Handler{},
			Token:  &token.Handler{},
			Client: &client.Handler{},
			OAuth:  &oauth.Handler{},
			Health: health.NewHandler(&mockPingChecker{}, &mockPingChecker{}),
		},
		metrics.NewTest(),
		noopRL, noopRL, noopRL,
		middleware.CORSConfig{AllowOrigins: "*", AllowMethods: "GET,POST", AllowHeaders: "Content-Type", ExposeHeaders: "X-Request-ID", MaxAge: "86400"},
		middleware.HSTSConfig{Enabled: false},
		zap.NewNop(),
	)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	assert.Empty(t, rec.Header().Get("Strict-Transport-Security"))
}

func TestAntiEnumeration_Login(t *testing.T) {
	srv := newSecurityTestServer()

	bodies := []string{
		`{"email":"existing@example.com","password":"wrong"}`,
		`{"email":"nonexistent@example.com","password":"wrong"}`,
	}

	var statuses []int
	var errorCodes []string

	for _, body := range bodies {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)

		statuses = append(statuses, rec.Code)

		var resp map[string]any
		if err := json.NewDecoder(rec.Body).Decode(&resp); err == nil {
			if code, ok := resp["code"].(string); ok {
				errorCodes = append(errorCodes, code)
			}
		}
	}

	// Both should return same status (no user enumeration)
	require.Len(t, statuses, 2)
	assert.Equal(t, statuses[0], statuses[1], "login responses should have same status for existing and non-existing users")
}

func TestAntiEnumeration_PasswordReset(t *testing.T) {
	srv := newSecurityTestServer()

	bodies := []string{
		`{"email":"existing@example.com"}`,
		`{"email":"nonexistent@example.com"}`,
	}

	var statuses []int

	for _, body := range bodies {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/reset-request", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)

		statuses = append(statuses, rec.Code)
	}

	require.Len(t, statuses, 2)
	assert.Equal(t, statuses[0], statuses[1], "password reset responses should have same status for existing and non-existing users")
}

func TestGenericErrorMessages(t *testing.T) {
	srv := newSecurityTestServer()

	// Send malformed requests — responses should not contain internal details
	endpoints := []struct {
		method string
		path   string
		body   string
	}{
		{http.MethodPost, "/api/v1/auth/login", "invalid json"},
		{http.MethodPost, "/api/v1/auth/register", "invalid json"},
		{http.MethodPost, "/api/v1/auth/token/refresh", "invalid json"},
	}

	for _, ep := range endpoints {
		t.Run(ep.method+" "+ep.path, func(t *testing.T) {
			req := httptest.NewRequest(ep.method, ep.path, strings.NewReader(ep.body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rec, req)

			body := rec.Body.String()
			// Should not contain stack traces or internal error details
			assert.NotContains(t, body, "goroutine")
			assert.NotContains(t, body, "panic")
			assert.NotContains(t, body, ".go:")
			assert.NotContains(t, body, "runtime.")
		})
	}
}

func TestRateLimitApplied(t *testing.T) {
	// Create server with blocking rate limiter to verify it's applied
	blockRL := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", "60")
			w.WriteHeader(http.StatusTooManyRequests)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "too many requests", "code": "RATE_LIMITED"})
		})
	}

	srv := rest.NewServer(
		&rest.Config{Host: "localhost", Port: 0, MetricsPort: 0},
		rest.Handlers{
			User:   &user.Handler{},
			Auth:   &auth.Handler{},
			Token:  &token.Handler{},
			Client: &client.Handler{},
			OAuth:  &oauth.Handler{},
			Health: health.NewHandler(&mockPingChecker{}, &mockPingChecker{}),
		},
		metrics.NewTest(),
		blockRL, blockRL, blockRL,
		middleware.CORSConfig{AllowOrigins: "*", AllowMethods: "GET,POST", AllowHeaders: "Content-Type", ExposeHeaders: "X-Request-ID", MaxAge: "86400"},
		middleware.HSTSConfig{Enabled: false},
		zap.NewNop(),
	)

	rateLimitedEndpoints := []struct {
		path string
		body string
	}{
		{"/api/v1/auth/login", `{"email":"a@b.com","password":"x"}`},
		{"/api/v1/auth/email/verify", `{"token":"x"}`},
		{"/api/v1/auth/password/reset-request", `{"email":"a@b.com"}`},
		{"/api/v1/auth/mfa/totp/verify", `{"code":"123456"}`},
		{"/api/v1/auth/mfa/recovery/verify", `{"code":"x"}`},
		{"/api/v1/auth/magic-link/request", `{"email":"a@b.com"}`},
	}

	for _, ep := range rateLimitedEndpoints {
		t.Run(ep.path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, ep.path, strings.NewReader(ep.body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rec, req)

			assert.Equal(t, http.StatusTooManyRequests, rec.Code, "endpoint %s should be rate limited", ep.path)
		})
	}
}
