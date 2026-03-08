package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractIP(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(*http.Request)
		expected string
	}{
		{
			name: "X-Real-IP header",
			setup: func(r *http.Request) {
				r.Header.Set("X-Real-IP", "1.2.3.4")
			},
			expected: "1.2.3.4",
		},
		{
			name: "X-Real-IP takes priority over X-Forwarded-For",
			setup: func(r *http.Request) {
				r.Header.Set("X-Real-IP", "1.2.3.4")
				r.Header.Set("X-Forwarded-For", "5.6.7.8")
			},
			expected: "1.2.3.4",
		},
		{
			name: "X-Forwarded-For single IP",
			setup: func(r *http.Request) {
				r.Header.Set("X-Forwarded-For", "10.0.0.1")
			},
			expected: "10.0.0.1",
		},
		{
			name: "X-Forwarded-For multiple IPs returns first",
			setup: func(r *http.Request) {
				r.Header.Set("X-Forwarded-For", "10.0.0.1, 10.0.0.2, 10.0.0.3")
			},
			expected: "10.0.0.1",
		},
		{
			name: "X-Forwarded-For with leading spaces",
			setup: func(r *http.Request) {
				r.Header.Set("X-Forwarded-For", "  192.168.1.1 , 10.0.0.2")
			},
			expected: "192.168.1.1",
		},
		{
			name: "fallback to RemoteAddr with port",
			setup: func(r *http.Request) {
				r.RemoteAddr = "192.168.0.1:12345"
			},
			expected: "192.168.0.1",
		},
		{
			name: "fallback to RemoteAddr without port",
			setup: func(r *http.Request) {
				r.RemoteAddr = "192.168.0.1"
			},
			expected: "192.168.0.1",
		},
		{
			name: "IPv6 RemoteAddr with port",
			setup: func(r *http.Request) {
				r.RemoteAddr = "[::1]:8080"
			},
			expected: "::1",
		},
		{
			name:     "no headers fallback to RemoteAddr",
			setup:    func(_ *http.Request) {},
			expected: "192.0.2.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = "192.0.2.1:1234"
			tt.setup(r)

			got := ExtractIP(r)
			assert.Equal(t, tt.expected, got)
		})
	}
}
