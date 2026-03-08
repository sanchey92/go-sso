package redis

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

var rateLimitScript = redis.NewScript(`
local current = redis.call("INCR", KEYS[1])
if current == 1 then
    redis.call("EXPIRE", KEYS[1], ARGV[1])
end
local ttl = redis.call("TTL", KEYS[1])
return {current, ttl}
`)

func (c *Cache) Allow(ctx context.Context, key string, maxAttempts int, window time.Duration) (bool, time.Duration, error) {
	windowSeconds := int64(window.Seconds())

	result, err := rateLimitScript.Run(ctx, c.client, []string{key}, windowSeconds).Slice()
	if err != nil {
		return false, 0, fmt.Errorf("rate limit script: %w", err)
	}

	current, ok := result[0].(int64)
	if !ok {
		return false, 0, fmt.Errorf("rate limit: unexpected count type %T", result[0])
	}

	ttl, ok := result[1].(int64)
	if !ok {
		return false, 0, fmt.Errorf("rate limit: unexpected ttl type: %T", result[1])
	}

	if current > int64(maxAttempts) {
		retryAfter := time.Duration(max(ttl, 1)) * time.Second
		return false, retryAfter, nil
	}

	return true, 0, nil
}
