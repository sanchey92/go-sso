package middleware

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/sanchey92/sso/pkg/metrics"
)

func MetricsMiddleware(m *metrics.Metrics) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			ww := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

			next.ServeHTTP(ww, r)

			duration := time.Since(start).Seconds()
			status := strconv.Itoa(ww.statusCode)
			path := normalizePath(r)

			m.HTTPRequestsTotal.WithLabelValues(r.Method, path, status).Inc()
			m.HTTPRequestDuration.WithLabelValues(r.Method, path).Observe(duration)
		})
	}
}

func normalizePath(r *http.Request) string {
	rctx := chi.RouteContext(r.Context())
	if rctx == nil {
		return "unknown"
	}

	routePattern := strings.Join(rctx.RoutePatterns, "")
	if routePattern == "" {
		return "unknown"
	}

	routePattern = strings.ReplaceAll(routePattern, "/*/", "/")
	return routePattern
}
