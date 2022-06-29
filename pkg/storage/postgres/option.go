package postgres

import (
	"time"
)

const (
	defaultExpiry      = time.Hour * 24
	defaultRegistryTTL = time.Second * 30
)

type config struct {
	expiry      time.Duration
	registryTTL time.Duration
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

func getConfig(options ...Option) *config {
	cfg := new(config)
	WithExpiry(defaultExpiry)(cfg)
	WithRegistryTTL(defaultRegistryTTL)(cfg)
	for _, o := range options {
		o(cfg)
	}
	return cfg
}
