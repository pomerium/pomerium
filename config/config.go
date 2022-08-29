package config

import (
	"crypto/tls"

	"github.com/pomerium/pomerium/internal/hashutil"
	"github.com/pomerium/pomerium/internal/telemetry/metrics"
)

// MetricsScrapeEndpoint defines additional metrics endpoints that would be scraped and exposed by pomerium
type MetricsScrapeEndpoint metrics.ScrapeEndpoint

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
	// MetricsPort is the port the metrics listener is running on.
	MetricsPort string
	// DebugPort is the port the debug listener is running on.
	DebugPort string
	// ACMETLSPort is the port that handles the ACME TLS-ALPN challenge.
	ACMETLSALPNPort string

	// MetricsScrapeEndpoints additional metrics endpoints to scrape and provide part of metrics
	MetricsScrapeEndpoints []MetricsScrapeEndpoint
}

// Clone creates a clone of the config.
func (cfg *Config) Clone() *Config {
	newOptions := new(Options)
	if cfg.Options != nil {
		*newOptions = *cfg.Options
	}

	endpoints := make([]MetricsScrapeEndpoint, len(cfg.MetricsScrapeEndpoints))
	_ = copy(endpoints, cfg.MetricsScrapeEndpoints)

	return &Config{
		Options:          newOptions,
		AutoCertificates: cfg.AutoCertificates,
		EnvoyVersion:     cfg.EnvoyVersion,

		GRPCPort:        cfg.GRPCPort,
		HTTPPort:        cfg.HTTPPort,
		OutboundPort:    cfg.OutboundPort,
		MetricsPort:     cfg.MetricsPort,
		DebugPort:       cfg.DebugPort,
		ACMETLSALPNPort: cfg.ACMETLSALPNPort,

		MetricsScrapeEndpoints: endpoints,
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

// AllocatePorts populates
func (cfg *Config) AllocatePorts(ports [6]string) {
	cfg.GRPCPort = ports[0]
	cfg.HTTPPort = ports[1]
	cfg.OutboundPort = ports[2]
	cfg.MetricsPort = ports[3]
	cfg.DebugPort = ports[4]
	cfg.ACMETLSALPNPort = ports[5]
}
