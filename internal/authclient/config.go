package authclient

import (
	"crypto/tls"
)

type config struct {
	tlsConfig *tls.Config
}

func getConfig(options ...Option) *config {
	cfg := new(config)
	for _, o := range options {
		o(cfg)
	}
	return cfg
}

// An Option modifies the config.
type Option func(*config)

// WithTLSConfig returns an option to configure the tls config.
func WithTLSConfig(tlsConfig *tls.Config) Option {
	return func(cfg *config) {
		cfg.tlsConfig = tlsConfig
	}
}
