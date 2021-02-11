package redis

import (
	"crypto/tls"
	"time"
)

type config struct {
	tls    *tls.Config
	expiry time.Duration
}

// Option customizes a Backend.
type Option func(*config)

// WithTLSConfig sets the tls.Config which Backend uses.
func WithTLSConfig(tlsConfig *tls.Config) Option {
	return func(cfg *config) {
		cfg.tls = tlsConfig
	}
}

// WithExpiry sets the expiry for changes.
func WithExpiry(expiry time.Duration) Option {
	return func(cfg *config) {
		cfg.expiry = expiry
	}
}

func getConfig(options ...Option) *config {
	cfg := new(config)
	for _, o := range options {
		o(cfg)
	}
	return cfg
}
