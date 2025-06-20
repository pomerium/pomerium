package postgres

import (
	"time"

	oteltrace "go.opentelemetry.io/otel/trace"
)

const (
	defaultExpiry      = time.Hour * 24
	defaultRegistryTTL = time.Second * 30
)

type config struct {
	expiry           time.Duration
	registryTTL      time.Duration
	tracerProvider   oteltrace.TracerProvider
	limitConcurrency bool
}

// Option customizes a Backend.
type Option func(*config)

// WithExpiry sets the expiry for changes.
func WithExpiry(expiry time.Duration) Option {
	return func(cfg *config) {
		cfg.expiry = expiry
	}
}

// WithRegistryTTL sets the default registry TTL.
func WithRegistryTTL(ttl time.Duration) Option {
	return func(cfg *config) {
		cfg.registryTTL = ttl
	}
}

func WithTracerProvider(tracerProvider oteltrace.TracerProvider) Option {
	return func(cfg *config) {
		cfg.tracerProvider = tracerProvider
	}
}

// WithLimitConcurrency enables or disables concurrent query limiting.
func WithLimitConcurrency(enable bool) Option {
	return func(cfg *config) {
		cfg.limitConcurrency = enable
	}
}

func getConfig(options ...Option) *config {
	cfg := new(config)
	WithExpiry(defaultExpiry)(cfg)
	WithRegistryTTL(defaultRegistryTTL)(cfg)
	WithLimitConcurrency(true)(cfg)
	for _, o := range options {
		o(cfg)
	}
	return cfg
}
