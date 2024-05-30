package reporter

import (
	"time"

	"go.opentelemetry.io/otel/metric"
)

type config struct {
	shutdownTimeout time.Duration
	collectInterval time.Duration
	metrics         []func(metric.Meter) error
}

// Option is a functional option for configuring the dialhome package.
type Option func(*config)

// WithShutdownTimeout sets the shutdown timeout to use for dialhome.
func WithShutdownTimeout(timeout time.Duration) Option {
	return func(c *config) {
		c.shutdownTimeout = timeout
	}
}

// WithCollectInterval sets the collect interval for metrics to be queried.
func WithCollectInterval(interval time.Duration) Option {
	return func(c *config) {
		c.collectInterval = interval
	}
}

// WithMetrics adds metrics to be collected
func WithMetrics(fns ...func(metric.Meter) error) Option {
	return func(c *config) {
		c.metrics = append(c.metrics, fns...)
	}
}

func getConfig(opts ...Option) *config {
	c := new(config)
	defaults := []Option{
		WithShutdownTimeout(time.Second * 5),
		WithCollectInterval(time.Hour),
	}
	for _, opt := range append(defaults, opts...) {
		opt(c)
	}
	return c
}
