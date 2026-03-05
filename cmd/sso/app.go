package main

import (
	"context"
	"fmt"
	"os/signal"
	"syscall"
	"time"

	"go.uber.org/zap"

	"github.com/sanchey92/sso/internal/adapter/driven/postgres"
	"github.com/sanchey92/sso/internal/adapter/driven/redis"
	"github.com/sanchey92/sso/internal/adapter/driving/rest"
	"github.com/sanchey92/sso/internal/config"
	"github.com/sanchey92/sso/pkg/logger"
)

type App struct {
	cfg        *config.Config
	log        *zap.Logger
	storage    *postgres.Storage
	cache      *redis.Cache
	httpServer *rest.Server
}

func NewApp(cfg *config.Config) (*App, error) {
	log := initLogger(cfg.Observability.Log)

	storage, err := initPostgres(&cfg.Database.Postgres, log)
	if err != nil {
		return nil, fmt.Errorf("postgres: %w", err)
	}

	cache, err := initCache(&cfg.Database.Redis, log)
	if err != nil {
		return nil, fmt.Errorf("redis: %w", err)
	}

	httpServer := rest.NewServer(&rest.Config{
		Host:         cfg.Server.HTTP.Host,
		Port:         cfg.Server.HTTP.Port,
		ReadTimeout:  cfg.Server.HTTP.ReadTimeout,
		WriteTimeout: cfg.Server.HTTP.WriteTimeout,
	}, log)

	return &App{
		cfg:        cfg,
		log:        log,
		storage:    storage,
		cache:      cache,
		httpServer: httpServer,
	}, nil
}

func (a *App) Run() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		if err := a.httpServer.Start(); err != nil {
			a.log.Fatal("http server error", zap.Error(err))
		}
	}()

	a.log.Info("app started")

	<-ctx.Done()
	a.Stop()
}

func (a *App) Stop() {
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := a.httpServer.Stop(shutdownCtx); err != nil {
		a.log.Error("http server shutdown error", zap.Error(err))
	}

	a.storage.Close()
	if err := a.cache.Close(); err != nil {
		a.log.Error("failed close redis", zap.Error(err))
	}
	a.log.Info("app stopped")
}

func initLogger(cfg config.LogConfig) *zap.Logger {
	return logger.New(&logger.Config{
		Level:  cfg.Level,
		Format: cfg.Format,
	})
}

func initPostgres(cfg *config.PostgresConfig, log *zap.Logger) (*postgres.Storage, error) {
	s, err := postgres.New(context.Background(), &postgres.Config{
		DSN:             cfg.DSN,
		MaxConns:        cfg.MaxConns,
		MinConns:        cfg.MinConns,
		MaxConnLifetime: cfg.MaxConnLifetime,
		MaxConnIdleTime: cfg.MaxConnIdleTime,
	}, log)
	if err != nil {
		return nil, fmt.Errorf("postgres.New: %w", err)
	}
	return s, nil
}

func initCache(cfg *config.RedisConfig, log *zap.Logger) (*redis.Cache, error) {
	c, err := redis.NewCache(&redis.Config{
		Address:         cfg.Addr,
		Password:        cfg.Password,
		DB:              cfg.DB,
		DialTimeout:     cfg.DialTimeout,
		ReadTimeout:     cfg.ReadTimeout,
		WriteTimeout:    cfg.WriteTimeout,
		PoolSize:        cfg.PoolSize,
		MinIdleConns:    cfg.MinIdleConns,
		ConnMaxIdleTime: cfg.ConnMaxIdleTime,
	}, log)
	if err != nil {
		return nil, fmt.Errorf("redis.NewCache: %w", err)
	}
	return c, nil
}
