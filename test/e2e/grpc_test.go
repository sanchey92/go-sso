//go:build e2e

package e2e

import (
	"fmt"
	"testing"

	goredis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	grpc_health_v1 "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	ssov1 "github.com/sanchey92/sso/gen/sso/v1"
	"github.com/sanchey92/sso/pkg/crypto"
)

func TestGRPC_IntrospectToken(t *testing.T) {
	flushRedis(t)

	const (
		email    = "introspect@test.com"
		password = "Password123!"
	)

	userID := registerUser(t, email, password)
	verifyEmail(t)
	accessToken, _ := loginUser(t, email, password)

	client, _ := grpcClient(t)
	ctx := grpcCtx(t)

	t.Run("active token", func(t *testing.T) {
		resp, err := client.IntrospectToken(ctx, &ssov1.IntrospectTokenRequest{
			Token: accessToken,
		})
		require.NoError(t, err)
		assert.True(t, resp.Active)
		assert.Equal(t, userID, resp.Subject)
		assert.NotEmpty(t, resp.Issuer)
		assert.NotNil(t, resp.ExpiresAt)
		assert.NotNil(t, resp.IssuedAt)
	})

	t.Run("cached introspection", func(t *testing.T) {
		// Second call should be served from cache — verify cache key exists in Redis.
		cacheKey := "introspect:" + crypto.HashToken(accessToken)

		rdb := goredis.NewClient(&goredis.Options{Addr: testRedisAddr})
		defer rdb.Close()

		val, err := rdb.Get(t.Context(), cacheKey).Result()
		require.NoError(t, err)
		assert.Contains(t, val, `"active":true`)

		// Call again — should still succeed (from cache).
		resp, err := client.IntrospectToken(ctx, &ssov1.IntrospectTokenRequest{
			Token: accessToken,
		})
		require.NoError(t, err)
		assert.True(t, resp.Active)
	})

	t.Run("invalid token", func(t *testing.T) {
		resp, err := client.IntrospectToken(ctx, &ssov1.IntrospectTokenRequest{
			Token: "invalid-token",
		})
		require.NoError(t, err)
		assert.False(t, resp.Active)
	})
}

func TestGRPC_ValidateToken(t *testing.T) {
	flushRedis(t)

	const (
		email    = "validate@test.com"
		password = "Password123!"
	)

	registerUser(t, email, password)
	verifyEmail(t)
	accessToken, _ := loginUser(t, email, password)

	client, _ := grpcClient(t)
	ctx := grpcCtx(t)

	t.Run("valid token", func(t *testing.T) {
		resp, err := client.ValidateToken(ctx, &ssov1.ValidateTokenRequest{
			Token: accessToken,
		})
		require.NoError(t, err)
		assert.True(t, resp.Valid)
		assert.NotEmpty(t, resp.UserId)
		assert.Equal(t, email, resp.Email)
		assert.True(t, resp.EmailVerified)
	})

	t.Run("invalid token", func(t *testing.T) {
		_, err := client.ValidateToken(ctx, &ssov1.ValidateTokenRequest{
			Token: "invalid-token",
		})
		require.Error(t, err)
		assert.Equal(t, codes.Unauthenticated, status.Code(err))
	})
}

func TestGRPC_GetUser(t *testing.T) {
	flushRedis(t)

	const (
		email    = "getuser@test.com"
		password = "Password123!"
	)

	userID := registerUser(t, email, password)
	verifyEmail(t)

	client, _ := grpcClient(t)
	ctx := grpcCtx(t)

	t.Run("existing user", func(t *testing.T) {
		resp, err := client.GetUser(ctx, &ssov1.GetUserRequest{
			UserId: userID,
		})
		require.NoError(t, err)
		assert.Equal(t, userID, resp.UserId)
		assert.Equal(t, email, resp.Email)
		assert.True(t, resp.EmailVerified)
		assert.False(t, resp.MfaEnabled)
		assert.NotNil(t, resp.CreatedAt)
	})

	t.Run("non-existing user", func(t *testing.T) {
		_, err := client.GetUser(ctx, &ssov1.GetUserRequest{
			UserId: "00000000-0000-0000-0000-000000000000",
		})
		require.Error(t, err)
		assert.Equal(t, codes.NotFound, status.Code(err))
	})
}

func TestGRPC_BatchValidateTokens(t *testing.T) {
	flushRedis(t)

	const password = "Password123!"

	var tokens []string
	for i := 0; i < 3; i++ {
		email := fmt.Sprintf("batch%d@test.com", i)
		registerUser(t, email, password)
		verifyEmail(t)
		accessToken, _ := loginUser(t, email, password)
		tokens = append(tokens, accessToken)
		flushRedis(t) // flush verify keys between registrations
	}

	client, _ := grpcClient(t)
	ctx := grpcCtx(t)

	t.Run("all valid", func(t *testing.T) {
		resp, err := client.BatchValidateTokens(ctx, &ssov1.BatchValidateTokensRequest{
			Tokens: tokens,
		})
		require.NoError(t, err)
		require.Len(t, resp.Results, 3)
		for _, r := range resp.Results {
			assert.True(t, r.Valid, "token should be valid: %s", r.Token)
			assert.NotEmpty(t, r.UserId)
		}
	})

	t.Run("mixed valid and invalid", func(t *testing.T) {
		mixed := []string{tokens[0], tokens[1], "invalid-token"}
		resp, err := client.BatchValidateTokens(ctx, &ssov1.BatchValidateTokensRequest{
			Tokens: mixed,
		})
		require.NoError(t, err)
		require.Len(t, resp.Results, 3)

		assert.True(t, resp.Results[0].Valid)
		assert.True(t, resp.Results[1].Valid)
		assert.False(t, resp.Results[2].Valid)
		assert.Empty(t, resp.Results[2].UserId)
	})
}

func TestGRPC_AuthInterceptor(t *testing.T) {
	t.Run("no API key", func(t *testing.T) {
		conn, err := grpc.NewClient(grpcAddr,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		)
		require.NoError(t, err)
		defer conn.Close()

		client := ssov1.NewSSOInternalServiceClient(conn)

		// Call without metadata.
		_, err = client.IntrospectToken(t.Context(), &ssov1.IntrospectTokenRequest{
			Token: "any",
		})
		require.Error(t, err)
		assert.Equal(t, codes.Unauthenticated, status.Code(err))
	})

	t.Run("wrong API key", func(t *testing.T) {
		conn, err := grpc.NewClient(grpcAddr,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		)
		require.NoError(t, err)
		defer conn.Close()

		client := ssov1.NewSSOInternalServiceClient(conn)
		ctx := grpcCtxWithKey(t, "wrong-api-key")

		_, err = client.IntrospectToken(ctx, &ssov1.IntrospectTokenRequest{
			Token: "any",
		})
		require.Error(t, err)
		assert.Equal(t, codes.Unauthenticated, status.Code(err))
	})
}

func TestGRPC_HealthCheck(t *testing.T) {
	conn, err := grpc.NewClient(grpcAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	defer conn.Close()

	client := grpc_health_v1.NewHealthClient(conn)

	// Health check should not require API key (exempted by auth interceptor).
	resp, err := client.Check(t.Context(), &grpc_health_v1.HealthCheckRequest{})
	require.NoError(t, err)
	assert.Equal(t, grpc_health_v1.HealthCheckResponse_SERVING, resp.Status)
}

func TestGRPC_AuthInterceptor_HealthBypass(t *testing.T) {
	// Health check should work even without API key metadata.
	conn, err := grpc.NewClient(grpcAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	defer conn.Close()

	client := grpc_health_v1.NewHealthClient(conn)

	md := metadata.Pairs("x-api-key", "wrong-key")
	ctx := metadata.NewOutgoingContext(t.Context(), md)

	resp, err := client.Check(ctx, &grpc_health_v1.HealthCheckRequest{})
	require.NoError(t, err)
	assert.Equal(t, grpc_health_v1.HealthCheckResponse_SERVING, resp.Status)
}
