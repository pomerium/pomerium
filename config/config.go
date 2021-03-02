package config

import (
	"crypto/tls"

	"github.com/pomerium/pomerium/internal/hashutil"
)

// Config holds pomerium configuration options.
type Config struct {
	Options          *Options
	AutoCertificates []tls.Certificate
}

// Clone creates a clone of the config.
func (cfg *Config) Clone() *Config {
	newOptions := new(Options)
	*newOptions = *cfg.Options
	return &Config{
		Options:          newOptions,
		AutoCertificates: cfg.AutoCertificates,
	}
}

// AllCertificates returns all the certificates in the config.
func (cfg *Config) AllCertificates() []tls.Certificate {
	var certs []tls.Certificate
	certs = append(certs, cfg.Options.Certificates...)
	certs = append(certs, cfg.AutoCertificates...)
	return certs
}

// Checksum returns the config checksum.
func (cfg *Config) Checksum() uint64 {
	return hashutil.MustHash(cfg)
}
