package interceptor

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestLoggingInterceptor(t *testing.T) {
	tests := []struct {
		name       string
		handler    grpc.UnaryHandler
		wantLevel  string
		wantFields map[string]string
	}{
		{
			name: "successful call",
			handler: func(_ context.Context, _ any) (any, error) {
				return "ok", nil
			},
			wantLevel: "info",
			wantFields: map[string]string{
				"method": "/sso.v1.SSOInternalService/IntrospectToken",
				"code":   "OK",
			},
		},
		{
			name: "error call",
			handler: func(_ context.Context, _ any) (any, error) {
				return nil, status.Error(codes.Unauthenticated, "bad token")
			},
			wantLevel: "error",
			wantFields: map[string]string{
				"method": "/sso.v1.SSOInternalService/ValidateToken",
				"code":   "Unauthenticated",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// observer — специальный zap core для тестирования
			core, logs := observer.New(zap.DebugLevel)
			log := zap.New(core)

			interceptor := LoggingInterceptor(log)
			info := &grpc.UnaryServerInfo{
				FullMethod: tt.wantFields["method"],
			}

			_, _ = interceptor(t.Context(), nil, info, tt.handler)

			require.Equal(t, 1, logs.Len(), "expected exactly 1 log entry")

			entry := logs.All()[0]

			// Проверяем уровень
			assert.Equal(t, tt.wantLevel, entry.Level.String())

			// Проверяем structured fields
			fieldMap := make(map[string]string)
			for _, f := range entry.ContextMap() {
				if s, ok := f.(string); ok {
					fieldMap[f.(string)] = s
				}
			}
			for _, f := range entry.Context {
				fieldMap[f.Key] = f.String
			}
			for key, want := range tt.wantFields {
				assert.Equal(t, want, fieldMap[key], "field %s", key)
			}

			// Проверяем что duration присутствует
			hasDuration := false
			for _, f := range entry.Context {
				if f.Key == "duration" {
					hasDuration = true
				}
			}
			assert.True(t, hasDuration, "log must contain duration field")
		})
	}
}
