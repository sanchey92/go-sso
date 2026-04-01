package interceptor

import (
	"context"
	"crypto/subtle"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const apiKeyHeader = "x-api-key"

func AuthInterceptor(apiKey string) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		if isHealthCheck(info.FullMethod) {
			return handler(ctx, req)
		}

		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "invalid or missing API key")
		}

		keys := md.Get(apiKeyHeader)
		if len(keys) == 0 {
			return nil, status.Error(codes.Unauthenticated, "invalid or missing API key")
		}

		if subtle.ConstantTimeCompare([]byte(keys[0]), []byte(apiKey)) != 1 {
			return nil, status.Error(codes.Unauthenticated, "invalid or missing API key")
		}

		return handler(ctx, req)
	}
}

func isHealthCheck(method string) bool {
	return method == "/grpc.health.v1.Health/Check" ||
		method == "/grpc.health.v1.Health/Watch"
}
