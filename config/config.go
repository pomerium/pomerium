package config

import "crypto/tls"

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
