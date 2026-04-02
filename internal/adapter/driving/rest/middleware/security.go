package middleware

import (
	"fmt"
	"net/http"
)

type HSTSConfig struct {
	Enabled bool
	MaxAge  int
}

func SecurityMiddleware(hsts HSTSConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()

			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("X-Frame-Options", "DENY")
			h.Set("X-XSS-Protection", "0")
			h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
			h.Set("Cache-Control", "no-store")
			h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")

			if hsts.Enabled {
				maxAge := hsts.MaxAge
				if maxAge <= 0 {
					maxAge = 31536000
				}
				h.Set("Strict-Transport-Security", fmt.Sprintf("max-age=%d; includeSubDomains", maxAge))
			}

			next.ServeHTTP(w, r)
		})
	}
}
