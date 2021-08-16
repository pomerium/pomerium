package config

import (
	"crypto/tls"

	"github.com/pomerium/pomerium/internal/hashutil"
)

// Config holds pomerium configuration options.
type Config struct {
	Options          *Options
	AutoCertificates []tls.Certificate
	EnvoyVersion     string

	// GRPCPort is the port the gRPC server is running on.
	GRPCPort string
	// HTTPPort is the port the HTTP server is running on.
	HTTPPort string
	// OutboundPort is the port the outbound gRPC listener is running on.
	OutboundPort string
}

// Clone creates a clone of the config.
func (cfg *Config) Clone() *Config {
	newOptions := new(Options)
	*newOptions = *cfg.Options
	return &Config{
		Options:          newOptions,
		AutoCertificates: cfg.AutoCertificates,
		EnvoyVersion:     cfg.EnvoyVersion,

		GRPCPort:     cfg.GRPCPort,
		HTTPPort:     cfg.HTTPPort,
		OutboundPort: cfg.OutboundPort,
	}
}

// AllCertificates returns all the certificates in the config.
func (cfg *Config) AllCertificates() ([]tls.Certificate, error) {
	optionCertificates, err := cfg.Options.GetCertificates()
	if err != nil {
		return nil, err
	}

	var certs []tls.Certificate
	certs = append(certs, optionCertificates...)
	certs = append(certs, cfg.AutoCertificates...)
	return certs, nil
}

// Checksum returns the config checksum.
func (cfg *Config) Checksum() uint64 {
	return hashutil.MustHash(cfg)
}
