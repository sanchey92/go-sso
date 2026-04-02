package middleware

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
)

type RateLimiter interface {
	Allow(ctx context.Context, key string, maxAttempts int, window time.Duration) (bool, time.Duration, error)
}

func RateLimit(
	limiter RateLimiter,
	maxAttempts int,
	window time.Duration,
	keyFunc func(*http.Request) string,
	log *zap.Logger,
) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := keyFunc(r)

			allowed, retryAfter, err := limiter.Allow(r.Context(), key, maxAttempts, window)
			if err != nil {
				log.Error("rate limit error",
					zap.Error(err),
					zap.String("key", key),
					zap.String("request_id", GetRequestID(r.Context())),
				)
				next.ServeHTTP(w, r)
				return
			}

			if !allowed {
				retrySeconds := strconv.Itoa(int(retryAfter.Seconds()))

				log.Warn("rate limit exceeded",
					zap.String("key", key),
					zap.String("retry_after", retrySeconds),
					zap.String("request_id", GetRequestID(r.Context())),
				)

				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Retry-After", retrySeconds)
				w.WriteHeader(http.StatusTooManyRequests)
				_ = json.NewEncoder(w).Encode(map[string]string{ //nolint:gosec // error writing response body is unrecoverable
					"error": "too many requests",
					"code":  "RATE_LIMITED",
				})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func ExtractIP(r *http.Request) string {
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	if xxf := r.Header.Get("X-Forwarded-For"); xxf != "" {
		for part := range strings.SplitSeq(xxf, ",") {
			ip := strings.TrimSpace(part)
			if ip != "" {
				return ip
			}
		}
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
