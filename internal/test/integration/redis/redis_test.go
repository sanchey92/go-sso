//go:build integration

package redis

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tcredis "github.com/testcontainers/testcontainers-go/modules/redis"
	"go.uber.org/zap"

	redisadapter "github.com/sanchey92/sso/internal/adapter/driven/redis"
	domainerrors "github.com/sanchey92/sso/internal/domain/errors"
)

var testCache *redisadapter.Cache

func TestMain(m *testing.M) {
	ctx := context.Background()

	ctr, err := tcredis.Run(ctx, "redis:7-alpine")
	if err != nil {
		panic("failed to start redis container: " + err.Error())
	}

	host, err := ctr.Host(ctx)
	if err != nil {
		panic("failed to get redis host: " + err.Error())
	}
	port, err := ctr.MappedPort(ctx, "6379")
	if err != nil {
		panic("failed to get redis port: " + err.Error())
	}

	cache, err := redisadapter.NewCache(&redisadapter.Config{
		Address:         fmt.Sprintf("%s:%s", host, port.Port()),
		DB:              0,
		DialTimeout:     5 * time.Second,
		ReadTimeout:     3 * time.Second,
		WriteTimeout:    3 * time.Second,
		PoolSize:        5,
		MinIdleConns:    1,
		ConnMaxIdleTime: time.Minute,
	}, zap.NewNop())
	if err != nil {
		panic("failed to create cache: " + err.Error())
	}

	testCache = cache

	code := m.Run()

	_ = cache.Close()
	_ = ctr.Terminate(ctx)

	os.Exit(code)
}

func TestCache_SetAndGet(t *testing.T) {
	ctx := t.Context()

	err := testCache.Set(ctx, "test:key", "hello", time.Minute)
	require.NoError(t, err)

	val, err := testCache.Get(ctx, "test:key")
	require.NoError(t, err)
	assert.Equal(t, "hello", val)
}

func TestCache_Get_KeyNotFound(t *testing.T) {
	_, err := testCache.Get(t.Context(), "nonexistent:key")
	require.ErrorIs(t, err, domainerrors.ErrKeyNotFound)
}

func TestCache_Delete(t *testing.T) {
	ctx := t.Context()

	err := testCache.Set(ctx, "delete:key", "value", time.Minute)
	require.NoError(t, err)

	err = testCache.Delete(ctx, "delete:key")
	require.NoError(t, err)

	_, err = testCache.Get(ctx, "delete:key")
	require.ErrorIs(t, err, domainerrors.ErrKeyNotFound)
}

func TestCache_TTL_Expiry(t *testing.T) {
	ctx := t.Context()

	err := testCache.Set(ctx, "ttl:key", "expires-soon", 500*time.Millisecond)
	require.NoError(t, err)

	// Key exists immediately.
	val, err := testCache.Get(ctx, "ttl:key")
	require.NoError(t, err)
	assert.Equal(t, "expires-soon", val)

	// Wait for TTL to expire.
	time.Sleep(700 * time.Millisecond)

	_, err = testCache.Get(ctx, "ttl:key")
	require.ErrorIs(t, err, domainerrors.ErrKeyNotFound)
}

func TestCache_Set_OverwritesExisting(t *testing.T) {
	ctx := t.Context()

	err := testCache.Set(ctx, "overwrite:key", "first", time.Minute)
	require.NoError(t, err)

	err = testCache.Set(ctx, "overwrite:key", "second", time.Minute)
	require.NoError(t, err)

	val, err := testCache.Get(ctx, "overwrite:key")
	require.NoError(t, err)
	assert.Equal(t, "second", val)
}

func TestCache_Delete_NonexistentKey(t *testing.T) {
	err := testCache.Delete(t.Context(), "ghost:key")
	require.NoError(t, err, "deleting a nonexistent key should not error")
}
