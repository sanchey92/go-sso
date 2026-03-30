package grpc

import (
	"context"
	"fmt"
	"net"

	"go.uber.org/zap"
	"google.golang.org/grpc"
)

type Config struct {
	Host string
	Port int
}

type Server struct {
	grpcServer *grpc.Server
	addr       string
	log        *zap.Logger
}

func NewServer(cfg *Config, log *zap.Logger) *Server {
	return &Server{
		grpcServer: grpc.NewServer(),
		addr:       fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		log:        log,
	}
}

func (s *Server) RegisterService(desc *grpc.ServiceDesc, impl any) {
	s.grpcServer.RegisterService(desc, impl)
}

func (s *Server) Start() error {
	s.log.Info("starting gRPC server", zap.String("addr", s.addr))

	lis, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("grpc listen %s: %w", s.addr, err)
	}

	if err := s.grpcServer.Serve(lis); err != nil {
		return fmt.Errorf("grpc serve: %w", err)
	}

	return nil
}

// Stop performs graceful shutdown of the gRPC server.
// It attempts GracefulStop first, which waits for in-flight RPCs to complete.
// If the context expires before GracefulStop finishes, it falls back to Stop()
// which forcefully closes all connections. The forced Stop also unblocks
// GracefulStop in the background goroutine, so no goroutine leak occurs.
func (s *Server) Stop(ctx context.Context) error {
	s.log.Info("stopping gRPC server")

	ch := make(chan struct{})
	go func() {
		s.grpcServer.GracefulStop()
		close(ch)
	}()

	select {
	case <-ch:
		s.log.Info("gRPC server stopped gracefully")
	case <-ctx.Done():
		s.log.Warn("gRPC graceful stop timed out, forcing stop")
		s.grpcServer.Stop()
		<-ch // wait for GracefulStop goroutine to finish — Stop() unblocks it
	}

	return nil
}
