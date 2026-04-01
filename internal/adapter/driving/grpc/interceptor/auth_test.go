package interceptor

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// noopHandler — заглушка handler-а, который всегда возвращает "ok"
func noopHandler(_ context.Context, _ any) (any, error) {
	return "ok", nil
}

func TestAuthInterceptor(t *testing.T) {
	const validKey = "test-api-key-123"
	interceptor := AuthInterceptor(validKey)

	tests := []struct {
		name     string
		ctx      context.Context
		method   string
		wantCode codes.Code
	}{
		{
			name: "valid API key",
			ctx: metadata.NewIncomingContext(
				t.Context(),
				metadata.Pairs("x-api-key", validKey),
			),
			method:   "/sso.v1.SSOInternalService/IntrospectToken",
			wantCode: codes.OK,
		},
		{
			name:     "missing metadata",
			ctx:      t.Context(),
			method:   "/sso.v1.SSOInternalService/IntrospectToken",
			wantCode: codes.Unauthenticated,
		},
		{
			name: "wrong API key",
			ctx: metadata.NewIncomingContext(
				t.Context(),
				metadata.Pairs("x-api-key", "wrong-key"),
			),
			method:   "/sso.v1.SSOInternalService/IntrospectToken",
			wantCode: codes.Unauthenticated,
		},
		{
			name:     "health check without key — allowed",
			ctx:      t.Context(),
			method:   "/grpc.health.v1.Health/Check",
			wantCode: codes.OK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := &grpc.UnaryServerInfo{FullMethod: tt.method}

			resp, err := interceptor(tt.ctx, nil, info, noopHandler)

			if tt.wantCode == codes.OK {
				require.NoError(t, err)
				assert.Equal(t, "ok", resp)
				return
			}

			require.Error(t, err)
			st, ok := status.FromError(err)
			require.True(t, ok)
			assert.Equal(t, tt.wantCode, st.Code())
		})
	}
}
