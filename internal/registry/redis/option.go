package redis

import (
	"crypto/tls"
	"time"
)

const defaultTTL = time.Second * 30

type config struct {
	tls    *tls.Config
	ttl    time.Duration
	getNow func() time.Time
}

// An Option modifies the config..
type Option func(*config)

// WithGetNow sets the time.Now function in the config.
func WithGetNow(getNow func() time.Time) Option {
	return func(cfg *config) {
		cfg.getNow = getNow
	}
}

// WithTLSConfig sets the tls.Config in the config.
func WithTLSConfig(tlsConfig *tls.Config) Option {
	return func(cfg *config) {
		cfg.tls = tlsConfig
	}
}

// WithTTL sets the ttl in the config.
func WithTTL(ttl time.Duration) Option {
	return func(cfg *config) {
		cfg.ttl = ttl
	}
}

func getConfig(options ...Option) *config {
	cfg := new(config)
	WithGetNow(time.Now)(cfg)
	WithTTL(defaultTTL)(cfg)
	for _, o := range options {
		o(cfg)
	}
	return cfg
}
