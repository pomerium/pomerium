package retry

import (
	"context"
	"reflect"
	"time"

	"github.com/cenkalti/backoff/v4"
)

type config struct {
	maxInterval     time.Duration
	initialInterval time.Duration
	watches         []watch

	backoff.BackOff
}

// watch is a helper struct to watch multiple channels
type watch struct {
	name string
	ch   reflect.Value
	fn   func(context.Context) error
	this bool
}

// Option configures the retry handler
type Option func(*config)

// WithWatch adds a watch to the retry handler
// that will be triggered when a value is received on the channel
// and the function will be called, also within a retry handler
func WithWatch[T any](name string, ch <-chan T, fn func(context.Context) error) Option {
	return func(cfg *config) {
		cfg.watches = append(cfg.watches, watch{name: name, ch: reflect.ValueOf(ch), fn: fn, this: false})
	}
}

// WithMaxInterval sets the upper bound for the retry handler
func WithMaxInterval(d time.Duration) Option {
	return func(cfg *config) {
		cfg.maxInterval = d
	}
}

// WithInitialInterval sets the initial backoff interval.
func WithInitialInterval(d time.Duration) Option {
	return func(cfg *config) {
		cfg.initialInterval = d
	}
}

func newConfig(opts ...Option) ([]watch, backoff.BackOff) {
	cfg := new(config)
	for _, opt := range []Option{
		WithMaxInterval(time.Minute * 5),
		WithInitialInterval(backoff.DefaultInitialInterval),
	} {
		opt(cfg)
	}

	for _, opt := range opts {
		opt(cfg)
	}

	for i, w := range cfg.watches {
		cfg.watches[i].fn = withRetry(cfg, w)
	}

	bo := backoff.NewExponentialBackOff()
	bo.InitialInterval = cfg.initialInterval
	bo.MaxInterval = cfg.maxInterval
	bo.MaxElapsedTime = 0
	bo.Multiplier = 2

	return cfg.watches, bo
}

func withRetry(cfg *config, w watch) func(context.Context) error {
	if w.fn == nil {
		return func(_ context.Context) error { return nil }
	}

	return func(ctx context.Context) error {
		return Retry(ctx, w.name, w.fn, WithMaxInterval(cfg.maxInterval))
	}
}
