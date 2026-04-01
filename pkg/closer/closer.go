package closer

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"sync"
	"time"

	"go.uber.org/zap"
)

const defaultShutdownTimeout = 5 * time.Second

type Closer struct {
	mu              sync.Mutex
	once            sync.Once
	done            chan struct{}
	funcs           []func(context.Context) error
	logger          *zap.Logger
	shutdownTimeout time.Duration
	err             error
}

func New(log *zap.Logger, shutdownTimeout time.Duration, signals ...os.Signal) *Closer {
	if shutdownTimeout <= 0 {
		shutdownTimeout = defaultShutdownTimeout
	}

	c := &Closer{
		done:            make(chan struct{}),
		logger:          log,
		shutdownTimeout: shutdownTimeout,
	}

	if len(signals) > 0 {
		go c.handleSignals(signals...)
	}

	return c
}

func (c *Closer) AddFunc(fn func(context.Context) error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	select {
	case <-c.done:
		c.logger.Warn("AddFunc called after Close, function will not be executed")
		return
	default:
	}

	c.funcs = append(c.funcs, fn)
}

func (c *Closer) handleSignals(signals ...os.Signal) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, signals...)
	defer signal.Stop(ch)

	select {
	case <-ch:
		c.logger.Info("signal detected, starting graceful shutdown")

		go func() {
			<-ch
			c.logger.Fatal("second signal received, forcing exit")
		}()

		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), c.shutdownTimeout)
		defer shutdownCancel()

		if err := c.CloseAll(shutdownCtx); err != nil {
			c.logger.Error("shutdown error", zap.Error(err))
		}
	case <-c.done:
	}
}

func (c *Closer) Wait() error {
	<-c.done
	return c.err
}

func (c *Closer) CloseAll(ctx context.Context) error {
	c.once.Do(func() {
		defer close(c.done)

		c.mu.Lock()
		funcs := c.funcs
		c.funcs = nil
		c.mu.Unlock()

		if len(funcs) == 0 {
			c.logger.Info("no functions to close")
			return
		}

		if ctx.Err() != nil {
			c.logger.Warn("context already cancelled, skipping shutdown", zap.Error(ctx.Err()))
			c.err = ctx.Err()
			return
		}

		c.logger.Info("closing all resources", zap.Int("count", len(funcs)))

		errCh := make(chan error, len(funcs))
		wg := &sync.WaitGroup{}

		for _, f := range funcs {
			wg.Go(func() {
				defer func() {
					if r := recover(); r != nil {
						errCh <- errors.New("panic recovered in closer")
						c.logger.Error("panic in close function", zap.Any("error", r))
					}
				}()

				if err := f(ctx); err != nil {
					errCh <- err
				}
			})
		}

		go func() {
			wg.Wait()
			close(errCh)
		}()

		for {
			select {
			case <-ctx.Done():
				c.logger.Warn("shutdown timeout exceeded", zap.Error(ctx.Err()))

				// Drain buffered errors. Check ok to avoid infinite loop
				// if errCh was closed between the outer select and this drain.
				for {
					select {
					case err, ok := <-errCh:
						if !ok {
							c.err = errors.Join(c.err, ctx.Err())
							return
						}
						c.logger.Error("close error", zap.Error(err))
						c.err = errors.Join(c.err, err)
					default:
						c.err = errors.Join(c.err, ctx.Err())
						return
					}
				}
			case err, ok := <-errCh:
				if !ok {
					c.logger.Info("all resources closed successfully")
					return
				}
				c.logger.Error("close error", zap.Error(err))
				c.err = errors.Join(c.err, err)
			}
		}
	})

	// Safe to read c.err without mutex: close(c.done) happens-before <-c.done,
	// and c.err is fully written before close(c.done) via defer ordering.
	<-c.done
	return c.err
}
