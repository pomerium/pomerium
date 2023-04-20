package config

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"

	"github.com/pomerium/pomerium/internal/fileutil"
	"github.com/pomerium/pomerium/internal/hashutil"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry/metrics"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/derivecert"
	"github.com/pomerium/pomerium/pkg/hpke"
)

// MetricsScrapeEndpoint defines additional metrics endpoints that would be scraped and exposed by pomerium
type MetricsScrapeEndpoint metrics.ScrapeEndpoint

// Config holds pomerium configuration options.
type Config struct {
	Options          *Options
	AutoCertificates []tls.Certificate
	EnvoyVersion     string

	// DerivedCertificates are TLS certificates derived from the shared secret
	DerivedCertificates []tls.Certificate
	// DerivedCAPEM is a PEM-encoded certificate authority
	// derived from the shared secret
	DerivedCAPEM []byte

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

		DerivedCertificates: cfg.DerivedCertificates,
		DerivedCAPEM:        cfg.DerivedCAPEM,
	}
}

// AllCertificateAuthoritiesPEM returns all CAs as PEM bundle bytes
func (cfg *Config) AllCertificateAuthoritiesPEM() ([]byte, error) {
	var combined bytes.Buffer
	if cfg.Options.CA != "" {
		bs, err := base64.StdEncoding.DecodeString(cfg.Options.CA)
		if err != nil {
			return nil, err
		}
		_, _ = combined.Write(bs)
		_, _ = combined.WriteRune('\n')
	}

	if cfg.Options.CAFile != "" {
		if err := fileutil.CopyFileUpTo(&combined, cfg.Options.CAFile, 5<<20); err != nil {
			return nil, err
		}
		_, _ = combined.WriteRune('\n')
	}

	if cfg.DerivedCAPEM != nil {
		_, _ = combined.Write(cfg.DerivedCAPEM)
		_, _ = combined.WriteRune('\n')
	}

	return combined.Bytes(), nil
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
	certs = append(certs, cfg.DerivedCertificates...)
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

// GetTLSClientConfig returns TLS configuration that accounts for additional CA entries
func (cfg *Config) GetTLSClientConfig() (*tls.Config, error) {
	roots, err := cfg.GetCertificatePool()
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		RootCAs:    roots,
		MinVersion: tls.VersionTLS12,
	}, nil
}

// GetCertificateForServerName gets the certificate for the server name. If no certificate is found and there
// is a derived CA one will be generated using that CA. If no derived CA is defined a self-signed certificate
// will be generated.
func (cfg *Config) GetCertificateForServerName(serverName string) (*tls.Certificate, error) {
	certificates, err := cfg.AllCertificates()
	if err != nil {
		return nil, err
	}

	// first try a direct name match
	for i := range certificates {
		if cryptutil.MatchesServerName(&certificates[i], serverName) {
			return &certificates[i], nil
		}
	}

	log.WarnNoTLSCertificate(serverName)

	if cfg.Options.DeriveInternalDomainCert != nil {
		sharedKey, err := cfg.Options.GetSharedKey()
		if err != nil {
			return nil, fmt.Errorf("failed to generate cert, invalid shared key: %w", err)
		}

		ca, err := derivecert.NewCA(sharedKey)
		if err != nil {
			return nil, fmt.Errorf("failed to generate cert, invalid derived CA: %w", err)
		}

		pem, err := ca.NewServerCert([]string{serverName})
		if err != nil {
			return nil, fmt.Errorf("failed to generate cert, error creating server certificate: %w", err)
		}

		cert, err := pem.TLS()
		if err != nil {
			return nil, fmt.Errorf("failed to generate cert, error converting generated certificate into TLS certificate: %w", err)
		}
		return &cert, nil
	}

	sharedKey, err := cfg.Options.GetSharedKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate cert, invalid shared key: %w", err)
	}

	// finally fall back to a generated, self-signed certificate
	return cryptutil.GenerateCertificate(sharedKey, serverName)
}

// WillHaveCertificateForServerName returns true if there will be a certificate for the given server name.
func (cfg *Config) WillHaveCertificateForServerName(serverName string) (bool, error) {
	certificates, err := cfg.AllCertificates()
	if err != nil {
		return false, err
	}

	// first try a direct name match
	for i := range certificates {
		if cryptutil.MatchesServerName(&certificates[i], serverName) {
			return true, nil
		}
	}

	return cfg.Options.DeriveInternalDomainCert != nil, nil
}

// GetCertificatePool gets the certificate pool for the config.
func (cfg *Config) GetCertificatePool() (*x509.CertPool, error) {
	pool, err := cryptutil.GetCertPool(cfg.Options.CA, cfg.Options.CAFile)
	if err != nil {
		return nil, err
	}

	if cfg.Options.DeriveInternalDomainCert != nil {
		sharedKey, err := cfg.Options.GetSharedKey()
		if err != nil {
			return nil, fmt.Errorf("failed to derive CA, invalid shared key: %w", err)
		}

		ca, err := derivecert.NewCA(sharedKey)
		if err != nil {
			return nil, fmt.Errorf("failed to derive CA: %w", err)
		}

		pem, err := ca.PEM()
		if err != nil {
			return nil, fmt.Errorf("failed to derive CA PEM: %w", err)
		}

		if !pool.AppendCertsFromPEM(pem.Cert) {
			return nil, fmt.Errorf("failed to derive CA PEM, error appending to pool")
		}
	}

	return pool, nil
}

// GetAuthenticateKeyFetcher returns a key fetcher for the authenticate service
func (cfg *Config) GetAuthenticateKeyFetcher() (hpke.KeyFetcher, error) {
	authenticateURL, transport, err := cfg.resolveAuthenticateURL()
	if err != nil {
		return nil, err
	}
	jwksURL := authenticateURL.ResolveReference(&url.URL{
		Path: urlutil.HPKEPublicKeyPath,
	}).String()
	return hpke.NewKeyFetcher(jwksURL, transport), nil
}

func (cfg *Config) resolveAuthenticateURL() (*url.URL, *http.Transport, error) {
	authenticateURL, err := cfg.Options.GetInternalAuthenticateURL()
	if err != nil {
		return nil, nil, fmt.Errorf("invalid authenticate service url: %w", err)
	}
	ok, err := cfg.WillHaveCertificateForServerName(authenticateURL.Hostname())
	if err != nil {
		return nil, nil, fmt.Errorf("error determining if authenticate service will have a certificate name: %w", err)
	}
	if !ok {
		return authenticateURL, httputil.GetInsecureTransport(), nil
	}

	transport, err := GetTLSClientTransport(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("get tls client config: %w", err)
	}

	return authenticateURL, transport, nil
}
