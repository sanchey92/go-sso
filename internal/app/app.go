package app

import (
	"context"
	"syscall"

	"go.uber.org/zap"

	"github.com/sanchey92/sso/internal/config"
	"github.com/sanchey92/sso/pkg/closer"
)

type App struct {
	log             *zap.Logger
	closer          *closer.Closer
	serviceProvider *serviceProvider
}

func NewApp(cfg *config.Config) (*App, error) {
	sp, err := newServiceProvider(cfg)
	if err != nil {
		return nil, err
	}

	c := closer.New(sp.log, cfg.Server.HTTP.ShutdownTimeout, syscall.SIGINT, syscall.SIGTERM)

	c.AddFunc(func(_ context.Context) error { sp.healthStop(); return nil })
	c.AddFunc(sp.httpServer.Stop)
	c.AddFunc(sp.grpcServer.Stop)
	if sp.tracingShutdown != nil {
		c.AddFunc(sp.tracingShutdown)
	}
	c.AddFunc(func(_ context.Context) error { return sp.cache.Close() })
	c.AddFunc(func(_ context.Context) error { sp.storage.Close(); return nil })

	return &App{
		log:             sp.log,
		closer:          c,
		serviceProvider: sp,
	}, nil
}

func (a *App) Run() {
	go func() {
		if err := a.serviceProvider.httpServer.Start(); err != nil {
			a.log.Error("http server error", zap.Error(err))
		}
	}()

	go func() {
		if err := a.serviceProvider.grpcServer.Start(); err != nil {
			a.log.Error("grpc server error", zap.Error(err))
		}
	}()

	a.log.Info("application started")

	if err := a.closer.Wait(); err != nil {
		a.log.Error("shutdown completed with errors", zap.Error(err))
	}

	a.log.Info("application stopped")
}
