package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/exaring/otelpgx"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/sanchey92/sso/pkg/metrics"
)

type Config struct {
	DSN             string
	MaxConns        int32
	MinConns        int32
	MaxConnLifetime time.Duration
	MaxConnIdleTime time.Duration
}

type Storage struct {
	pool *pgxpool.Pool
	log  *zap.Logger
}

func New(ctx context.Context, cfg *Config, m *metrics.Metrics, log *zap.Logger) (*Storage, error) {
	pgConfig, err := pgxpool.ParseConfig(cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("failed to parse dsn: %w", err)
	}
	pgConfig.MaxConns = cfg.MaxConns
	pgConfig.MinConns = cfg.MinConns
	pgConfig.MaxConnLifetime = cfg.MaxConnLifetime
	pgConfig.MaxConnIdleTime = cfg.MaxConnIdleTime
	pgConfig.ConnConfig.Tracer = newCompositeTracer(
		NewQueryTracer(m), // Prometheus метрики
		otelpgx.NewTracer( // OTel spans
			otelpgx.WithTrimSQLInSpanName(),
		),
	)

	pool, err := pgxpool.NewWithConfig(ctx, pgConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create db pool: %w", err)
	}
	if err = pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}
	return &Storage{
		pool: pool,
		log:  log,
	}, nil
}

func (s *Storage) Ping(ctx context.Context) error {
	if err := s.pool.Ping(ctx); err != nil {
		return fmt.Errorf("postgres ping: %w", err)
	}
	return nil
}

func (s *Storage) Pool() *pgxpool.Pool {
	return s.pool
}

func (s *Storage) Close() {
	s.pool.Close()
}
