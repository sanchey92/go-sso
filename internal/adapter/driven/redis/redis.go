package redis

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	domainerrors "github.com/sanchey92/sso/internal/domain/errors"
)

type Config struct {
	Address         string
	Password        string //nolint:gosec // not a hardcoded credential, loaded from config
	DB              int
	DialTimeout     time.Duration
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	PoolSize        int
	MinIdleConns    int
	ConnMaxIdleTime time.Duration
}

type Cache struct {
	client *redis.Client
	log    *zap.Logger
}

func NewCache(config *Config, log *zap.Logger) (*Cache, error) {
	client := redis.NewClient(&redis.Options{
		Addr:            config.Address,
		Password:        config.Password,
		DB:              config.DB,
		DialTimeout:     config.DialTimeout,
		ReadTimeout:     config.ReadTimeout,
		WriteTimeout:    config.WriteTimeout,
		PoolSize:        config.PoolSize,
		MinIdleConns:    config.MinIdleConns,
		ConnMaxIdleTime: config.ConnMaxIdleTime,
	})

	ctx, cancel := context.WithTimeout(context.Background(), config.DialTimeout)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("redis ping: %w", err)
	}

	return &Cache{
		client: client,
		log:    log,
	}, nil
}

func (c *Cache) Close() error {
	if err := c.client.Close(); err != nil {
		return fmt.Errorf("redis close: %w", err)
	}
	return nil
}

func (c *Cache) Set(ctx context.Context, key, val string, ttl time.Duration) error {
	if err := c.client.Set(ctx, key, val, ttl).Err(); err != nil {
		return fmt.Errorf("redis set %q: %w", key, err)
	}
	return nil
}

func (c *Cache) Get(ctx context.Context, key string) (string, error) {
	val, err := c.client.Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return "", domainerrors.ErrKeyNotFound
		}
		return "", fmt.Errorf("redis get %q: %w", key, err)
	}
	return val, nil
}

func (c *Cache) Delete(ctx context.Context, key string) error {
	if err := c.client.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("redis del %q: %w", key, err)
	}
	return nil
}
