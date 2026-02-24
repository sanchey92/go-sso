package main

import (
	"context"
	"fmt"
	"os/signal"
	"syscall"

	"go.uber.org/zap"

	"github.com/sanchey92/sso/internal/adapter/driven/postgres"
	"github.com/sanchey92/sso/internal/config"
	"github.com/sanchey92/sso/pkg/logger"
)

type App struct {
	cfg     *config.Config
	log     *zap.Logger
	storage *postgres.Storage
}

func NewApp(cfg *config.Config) (*App, error) {
	log := initLogger(cfg.Observability.Log)

	storage, err := initPostgres(cfg.Database.Postgres, log)
	if err != nil {
		return nil, fmt.Errorf("postgres: %w", err)
	}

	return &App{
		cfg:     cfg,
		log:     log,
		storage: storage,
	}, nil
}

func (a *App) Run() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	a.log.Info("app started")

	//....

	<-ctx.Done()
	a.Stop()
}

func (a *App) Stop() {
	a.storage.Close()
	a.log.Info("app stopped")
}

func initLogger(cfg config.LogConfig) *zap.Logger {
	return logger.New(&logger.Config{
		Level:  cfg.Level,
		Format: cfg.Format,
	})
}

func initPostgres(cfg config.PostgresConfig, log *zap.Logger) (*postgres.Storage, error) {
	return postgres.New(context.Background(), &postgres.Config{
		DSN:             cfg.DSN,
		MaxConns:        cfg.MaxConns,
		MinConns:        cfg.MinConns,
		MaxConnLifetime: cfg.MaxConnLifetime,
		MaxConnIdleTime: cfg.MaxConnIdleTime,
	}, log)
}
