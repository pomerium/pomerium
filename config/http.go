package config

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"sync"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/outbound"
	"github.com/pomerium/pomerium/internal/tripper"
	"github.com/pomerium/pomerium/pkg/cryptutil"
)

// NewHTTPTransport creates a new http transport. If CA or CAFile is set, the transport will
// add the CA to system cert pool. The transport, and its clones, use the proxy chosen by
// the current config's outbound proxy options (see [GlobalOptions.OutboundHttpProxy]),
// or by the HTTP_PROXY, HTTPS_PROXY and NO_PROXY environment variables if none is set.
// Their connections are closed when those settings change.
func NewHTTPTransport(src Source) *http.Transport {
	return newOutboundHTTP(src).Transport()
}

// newOutboundHTTP creates an [outbound.HTTP] that follows the config of src.
func newOutboundHTTP(src Source) *outbound.HTTP {
	o := outbound.New()
	var (
		mu      sync.Mutex
		rootCAs *x509.CertPool
	)
	update := func(ctx context.Context, cfg *Config) {
		mu.Lock()
		defer mu.Unlock()
		s := loadOutboundProxySettings(ctx, cfg.Options)
		// On error, the previous CA pool is kept.
		if pool, err := cryptutil.GetCertPool(cfg.Options.CA, cfg.Options.CAFile); err != nil {
			log.Ctx(ctx).Error().Err(err).Msg("config: error getting cert pool")
		} else {
			rootCAs = pool
		}
		s.RootCAs = rootCAs
		o.Update(ctx, s)
	}
	src.OnConfigChange(context.Background(), update)
	update(context.Background(), src.GetConfig())
	return o
}

func (o *Options) outboundProxyOptions() outbound.ProxyOptions {
	return outbound.ProxyOptions{
		HTTPProxy:  o.OutboundHttpProxy,
		HTTPSProxy: o.OutboundHttpsProxy,
		NoProxy:    o.OutboundNoProxy,
	}
}

// loadOutboundProxySettings returns the proxy settings for the outbound proxy
// options of o (see [outbound.ProxySettings]), logging an invalid option.
func loadOutboundProxySettings(ctx context.Context, o *Options) outbound.Settings {
	s := outbound.ProxySettings(o.outboundProxyOptions())
	if s.ProxyErr != nil {
		log.Ctx(ctx).Error().Err(s.ProxyErr).Msg("config: outbound requests will fail until the outbound proxy settings are fixed")
	}
	return s
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
