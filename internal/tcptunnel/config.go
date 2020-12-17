package tcptunnel

import (
	"crypto/tls"

	"github.com/pomerium/pomerium/internal/cliutil"
	"github.com/pomerium/pomerium/internal/log"
)

type config struct {
	jwtCache  cliutil.JWTCache
	dstHost   string
	proxyHost string
	tlsConfig *tls.Config
}

func getConfig(options ...Option) *config {
	cfg := new(config)
	if jwtCache, err := cliutil.NewLocalJWTCache(); err == nil {
		WithJWTCache(jwtCache)(cfg)
	} else {
		log.Error().Err(err).Msg("tcptunnel: error creating local JWT cache, using in-memory JWT cache")
		WithJWTCache(cliutil.NewMemoryJWTCache())(cfg)
	}
	for _, o := range options {
		o(cfg)
	}
	return cfg
}

// An Option modifies the config.
type Option func(*config)

// WithDestinationHost returns an option to configure the destination host.
func WithDestinationHost(dstHost string) Option {
	return func(cfg *config) {
		cfg.dstHost = dstHost
	}
}

// WithJWTCache returns an option to configure the jwt cache.
func WithJWTCache(jwtCache cliutil.JWTCache) Option {
	return func(cfg *config) {
		cfg.jwtCache = jwtCache
	}
}

// WithProxyHost returns an option to configure the proxy host.
func WithProxyHost(proxyHost string) Option {
	return func(cfg *config) {
		cfg.proxyHost = proxyHost
	}
}

// WithTLSConfig returns an option to configure the tls config.
func WithTLSConfig(tlsConfig *tls.Config) Option {
	return func(cfg *config) {
		cfg.tlsConfig = tlsConfig
	}
}
