package config

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"sync/atomic"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/tripper"
	"github.com/pomerium/pomerium/pkg/cryptutil"
)

// NewHTTPTransport creates a new http transport. If CA or CAFile is set, the transport will
// add the CA to system cert pool.
func NewHTTPTransport(src Source) *http.Transport {
	var rootCAs atomic.Pointer[x509.CertPool]
	update := func(ctx context.Context, cfg *Config) {
		if pool, err := cryptutil.GetCertPool(cfg.Options.CA, cfg.Options.CAFile); err != nil {
			log.Ctx(ctx).Error().Err(err).Msg("config: error getting cert pool")
		} else {
			rootCAs.Store(pool)
		}
	}
	src.OnConfigChange(context.Background(), update)
	update(context.Background(), src.GetConfig())

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		d := &tls.Dialer{Config: &tls.Config{
			RootCAs:    rootCAs.Load(),
			MinVersion: tls.VersionTLS12,
		}}
		return d.DialContext(ctx, network, addr)
	}
	// Through a proxy, the TLS handshake with the origin uses TLSClientConfig
	// rather than DialTLSContext. The CA pool can change with the config, so
	// the server certificate is verified against the current pool here.
	transport.TLSClientConfig = &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, // verified by VerifyConnection
		VerifyConnection: func(cs tls.ConnectionState) error {
			return verifyServerCertificate(cs, rootCAs.Load())
		},
	}
	transport.ForceAttemptHTTP2 = true
	return transport
}

// verifyServerCertificate verifies the server certificate chain against
// rootCAs and the server name, like crypto/tls does when InsecureSkipVerify is
// false. cs.ServerName is the SNI, which is empty when the server is addressed
// by IP, so such servers are rejected rather than accepted without a name
// check.
func verifyServerCertificate(cs tls.ConnectionState, rootCAs *x509.CertPool) error {
	if len(cs.PeerCertificates) == 0 {
		return errors.New("tls: server presented no certificates")
	}
	var err error
	if cs.ServerName == "" {
		err = errors.New("cannot verify a server addressed by IP through a proxy")
	} else {
		intermediates := x509.NewCertPool()
		for _, cert := range cs.PeerCertificates[1:] {
			intermediates.AddCert(cert)
		}
		_, err = cs.PeerCertificates[0].Verify(x509.VerifyOptions{
			DNSName:       cs.ServerName,
			Roots:         rootCAs,
			Intermediates: intermediates,
		})
	}
	if err != nil {
		return &tls.CertificateVerificationError{UnverifiedCertificates: cs.PeerCertificates, Err: err}
	}
	return nil
}

// NewPolicyHTTPTransport creates a new http RoundTripper for a policy.
func NewPolicyHTTPTransport(options *Options, policy *Policy, disableHTTP2 bool) http.RoundTripper {
	transport := http.DefaultTransport.(interface {
		Clone() *http.Transport
	}).Clone()
	c := tripper.NewChain()

	// according to the docs:
	//
	//    Programs that must disable HTTP/2 can do so by setting Transport.TLSNextProto (for clients) or
	//    Server.TLSNextProto (for servers) to a non-nil, empty map.
	//
	if disableHTTP2 {
		transport.TLSNextProto = map[string]func(authority string, c *tls.Conn) http.RoundTripper{}
		transport.ForceAttemptHTTP2 = false
	}

	var tlsClientConfig tls.Config
	var isCustomClientConfig bool

	if policy.TLSSkipVerify {
		tlsClientConfig.InsecureSkipVerify = true
		isCustomClientConfig = true
	}

	if options.CA != "" || options.CAFile != "" {
		rootCAs, err := cryptutil.GetCertPool(options.CA, options.CAFile)
		if err == nil {
			tlsClientConfig.RootCAs = rootCAs
			tlsClientConfig.MinVersion = tls.VersionTLS12
			isCustomClientConfig = true
		} else {
			log.Error().Err(err).Msg("config: error getting ca cert pool")
		}
	}

	if policy.TLSCustomCA != "" || policy.TLSCustomCAFile != "" {
		rootCAs, err := cryptutil.GetCertPool(policy.TLSCustomCA, policy.TLSCustomCAFile)
		if err == nil {
			tlsClientConfig.RootCAs = rootCAs
			tlsClientConfig.MinVersion = tls.VersionTLS12
			isCustomClientConfig = true
		} else {
			log.Error().Err(err).Msg("config: error getting custom ca cert pool")
		}
	}

	if policy.ClientCertificate != nil {
		tlsClientConfig.Certificates = []tls.Certificate{*policy.ClientCertificate}
		isCustomClientConfig = true
	}

	if policy.TLSServerName != "" {
		tlsClientConfig.ServerName = policy.TLSServerName
		isCustomClientConfig = true
	}
	if policy.TLSUpstreamServerName != "" {
		tlsClientConfig.ServerName = policy.TLSUpstreamServerName
		isCustomClientConfig = true
	}

	// We avoid setting a custom client config unless we have to as
	// if TLSClientConfig is nil, the default configuration is used.
	if isCustomClientConfig {
		transport.DialTLSContext = nil
		transport.TLSClientConfig = &tlsClientConfig
	}
	return c.Then(transport)
}

// GetTLSClientTransport returns http transport accounting for custom CAs from config
func GetTLSClientTransport(cfg *Config) (*http.Transport, error) {
	tlsConfig, err := cfg.GetTLSClientConfig()
	if err != nil {
		return nil, err
	}
	return &http.Transport{
		TLSClientConfig:   tlsConfig,
		ForceAttemptHTTP2: true,
	}, nil
}
