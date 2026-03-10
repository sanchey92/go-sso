package closer

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name        string
		timeout     time.Duration
		wantTimeout time.Duration
	}{
		{
			name:        "zero timeout uses default",
			timeout:     0,
			wantTimeout: defaultShutdownTimeout,
		},
		{
			name:        "negative timeout uses default",
			timeout:     -1 * time.Second,
			wantTimeout: defaultShutdownTimeout,
		},
		{
			name:        "custom timeout",
			timeout:     10 * time.Second,
			wantTimeout: 10 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := New(zap.NewNop(), tt.timeout)

			require.NotNil(t, c)
			assert.NotNil(t, c.done)
			assert.Empty(t, c.funcs)
			assert.Equal(t, tt.wantTimeout, c.shutdownTimeout)
		})
	}
}

func TestAddFunc(t *testing.T) {
	tests := []struct {
		name      string
		addCount  int
		wantCount int
	}{
		{
			name:      "single function",
			addCount:  1,
			wantCount: 1,
		},
		{
			name:      "multiple functions",
			addCount:  3,
			wantCount: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := New(zap.NewNop(), defaultShutdownTimeout)

			for range tt.addCount {
				c.AddFunc(func(_ context.Context) error { return nil })
			}

			assert.Len(t, c.funcs, tt.wantCount)
		})
	}
}

func TestAddFunc_AfterClose(t *testing.T) {
	c := New(zap.NewNop(), defaultShutdownTimeout)

	err := c.CloseAll(t.Context())
	require.NoError(t, err)

	c.AddFunc(func(_ context.Context) error { return nil })

	c.mu.Lock()
	assert.Nil(t, c.funcs, "function must not be added after close")
	c.mu.Unlock()
}

func TestCloseAll(t *testing.T) {
	errDB := errors.New("db close failed")
	errRedis := errors.New("redis close failed")

	tests := []struct {
		name   string
		setup  func(c *Closer)
		ctx    func(t *testing.T) context.Context
		assert func(t *testing.T, c *Closer, err error)
	}{
		{
			name:  "no functions",
			setup: func(_ *Closer) {},
			assert: func(t *testing.T, _ *Closer, err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "all functions called",
			setup: func(c *Closer) {
				var called atomic.Int32
				for range 3 {
					c.AddFunc(func(_ context.Context) error {
						called.Add(1)
						return nil
					})
				}
				t.Cleanup(func() {
					assert.Equal(t, int32(3), called.Load())
				})
			},
			assert: func(t *testing.T, _ *Closer, err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "single error",
			setup: func(c *Closer) {
				c.AddFunc(func(_ context.Context) error { return errDB })
				c.AddFunc(func(_ context.Context) error { return nil })
			},
			assert: func(t *testing.T, _ *Closer, err error) {
				require.Error(t, err)
				assert.ErrorIs(t, err, errDB)
			},
		},
		{
			name: "collects all errors",
			setup: func(c *Closer) {
				c.AddFunc(func(_ context.Context) error { return errDB })
				c.AddFunc(func(_ context.Context) error { return nil })
				c.AddFunc(func(_ context.Context) error { return errRedis })
			},
			assert: func(t *testing.T, _ *Closer, err error) {
				require.Error(t, err)
				assert.ErrorIs(t, err, errDB)
				assert.ErrorIs(t, err, errRedis)
			},
		},
		{
			name: "idempotent - second call returns nil and does not re-execute",
			setup: func(c *Closer) {
				var called atomic.Int32
				c.AddFunc(func(_ context.Context) error {
					called.Add(1)
					return nil
				})
				_ = c.CloseAll(context.Background())
				t.Cleanup(func() {
					assert.Equal(t, int32(1), called.Load(), "function must be called exactly once")
				})
			},
			assert: func(t *testing.T, _ *Closer, err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "context timeout returns error",
			setup: func(c *Closer) {
				c.AddFunc(func(ctx context.Context) error {
					<-ctx.Done()
					return nil
				})
			},
			ctx: func(t *testing.T) context.Context {
				ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
				t.Cleanup(cancel)
				return ctx
			},
			assert: func(t *testing.T, _ *Closer, err error) {
				require.Error(t, err)
				assert.ErrorIs(t, err, context.DeadlineExceeded)
			},
		},
		{
			name: "recovers from panic",
			setup: func(c *Closer) {
				c.AddFunc(func(_ context.Context) error {
					panic("something went wrong")
				})
				c.AddFunc(func(_ context.Context) error { return nil })
			},
			assert: func(t *testing.T, _ *Closer, err error) {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "panic recovered in closer")
			},
		},
		{
			name: "clears funcs after close",
			setup: func(c *Closer) {
				c.AddFunc(func(_ context.Context) error { return nil })
			},
			assert: func(t *testing.T, c *Closer, err error) {
				require.NoError(t, err)
				c.mu.Lock()
				assert.Nil(t, c.funcs)
				c.mu.Unlock()
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := New(zap.NewNop(), defaultShutdownTimeout)
			tt.setup(c)

			ctx := t.Context()
			if tt.ctx != nil {
				ctx = tt.ctx(t)
			}

			err := c.CloseAll(ctx)

			tt.assert(t, c, err)
		})
	}
}

func TestCloseAll_Concurrent(t *testing.T) {
	errDB := errors.New("db close failed")
	c := New(zap.NewNop(), defaultShutdownTimeout)
	var called atomic.Int32

	c.AddFunc(func(_ context.Context) error {
		called.Add(1)
		return errDB
	})

	errs := make([]error, 10)
	var wg sync.WaitGroup
	for i := range 10 {
		wg.Go(func() {
			errs[i] = c.CloseAll(t.Context())
		})
	}
	wg.Wait()

	assert.Equal(t, int32(1), called.Load())
	for i, err := range errs {
		assert.ErrorIs(t, err, errDB, "caller %d must see the error", i)
	}
}

func TestCloseAll_AlreadyCancelledContext(t *testing.T) {
	c := New(zap.NewNop(), defaultShutdownTimeout)
	var called atomic.Bool

	c.AddFunc(func(_ context.Context) error {
		called.Store(true)
		return nil
	})

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	err := c.CloseAll(ctx)

	require.ErrorIs(t, err, context.Canceled)
	assert.False(t, called.Load(), "function must not be called with cancelled context")
}

func TestCloseAll_TimeoutPreservesBufferedErrors(t *testing.T) {
	errDB := errors.New("db close failed")
	c := New(zap.NewNop(), defaultShutdownTimeout)

	// Function that returns an error immediately.
	c.AddFunc(func(_ context.Context) error { return errDB })
	// Function that blocks until context is cancelled.
	c.AddFunc(func(ctx context.Context) error {
		<-ctx.Done()
		return nil
	})

	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	t.Cleanup(cancel)

	err := c.CloseAll(ctx)

	require.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.ErrorIs(t, err, errDB, "buffered error must not be lost on timeout")
}

func TestHandleSignals(t *testing.T) {
	c := New(zap.NewNop(), 2*time.Second, syscall.SIGUSR1)
	var called atomic.Bool

	c.AddFunc(func(_ context.Context) error {
		called.Store(true)
		return nil
	})

	time.Sleep(20 * time.Millisecond)

	err := syscall.Kill(syscall.Getpid(), syscall.SIGUSR1)
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		return called.Load()
	}, 2*time.Second, 10*time.Millisecond)
}
