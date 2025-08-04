package postgres

import (
	"time"

	oteltrace "go.opentelemetry.io/otel/trace"
)

const (
	defaultRegistryTTL = time.Second * 30
)

type config struct {
	registryTTL    time.Duration
	tracerProvider oteltrace.TracerProvider
}

// Option customizes a Backend.
type Option func(*config)

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

func getConfig(options ...Option) *config {
	cfg := new(config)
	WithRegistryTTL(defaultRegistryTTL)(cfg)
	for _, o := range options {
		o(cfg)
	}
	return cfg
}
