package postgres

import (
	"time"
)

const defaultExpiry = time.Hour * 24

type config struct {
	expiry time.Duration
}

// Option customizes a Backend.
type Option func(*config)

// WithExpiry sets the expiry for changes.
func WithExpiry(expiry time.Duration) Option {
	return func(cfg *config) {
		cfg.expiry = expiry
	}
}

func getConfig(options ...Option) *config {
	cfg := new(config)
	WithExpiry(defaultExpiry)(cfg)
	for _, o := range options {
		o(cfg)
	}
	return cfg
}
