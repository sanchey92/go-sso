package middleware

import (
	"net/http"

	"github.com/riandyrn/otelchi"
)

func TracingMiddleware(serviceName string) func(http.Handler) http.Handler {
	return otelchi.Middleware(serviceName)
}
