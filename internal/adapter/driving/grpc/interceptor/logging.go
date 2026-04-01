package interceptor

import (
	"context"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
)

func LoggingInterceptor(log *zap.Logger) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		start := time.Now()

		resp, err := handler(ctx, req)
		st, _ := status.FromError(err)
		duration := time.Since(start)

		if err != nil {
			log.Error("grpc request",
				zap.String("method", info.FullMethod),
				zap.String("code", st.Code().String()),
				zap.Duration("duration", duration),
			)
		} else {
			log.Info("grpc request",
				zap.String("method", info.FullMethod),
				zap.String("code", st.Code().String()),
				zap.Duration("duration", duration),
			)
		}

		return resp, err
	}
}
