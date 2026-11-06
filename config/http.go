package config

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"

	"golang.org/x/net/http/httpproxy"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/tripper"
	"github.com/pomerium/pomerium/pkg/cryptutil"
)

// httpTransportState is the config-derived state of a transport created by
// NewHTTPTransport.
type httpTransportState struct {
	proxy   func(*http.Request) (*url.URL, error)
	rootCAs *x509.CertPool
}

// NewHTTPTransport creates a new http transport. If CA or CAFile is set, the transport will
// add the CA to system cert pool. The transport, and its clones, use the proxy chosen by
// the current config's outbound proxy options (see [GlobalOptions.OutboundHttpProxy]),
// or by the HTTP_PROXY, HTTPS_PROXY and NO_PROXY environment variables if none is set.
func NewHTTPTransport(src Source) *http.Transport {
	var state atomic.Pointer[httpTransportState]
	update := func(ctx context.Context, cfg *Config) {
		next := httpTransportState{proxy: outboundProxyFunc(cfg.Options)}
		if prev := state.Load(); prev != nil {
			next.rootCAs = prev.rootCAs
		}
		if rootCAs, err := cryptutil.GetCertPool(cfg.Options.CA, cfg.Options.CAFile); err != nil {
			log.Ctx(ctx).Error().Err(err).Msg("config: error getting cert pool")
		} else {
			next.rootCAs = rootCAs
		}
		state.Store(&next)
	}
	src.OnConfigChange(context.Background(), update)
	update(context.Background(), src.GetConfig())

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = func(req *http.Request) (*url.URL, error) {
		return state.Load().proxy(req)
	}
	transport.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		d := &tls.Dialer{Config: &tls.Config{
			RootCAs:    state.Load().rootCAs,
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
			return verifyServerCertificate(cs, state.Load().rootCAs)
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

// outboundProxyFunc returns the proxy function for Pomerium's own outbound
// HTTP requests: the outbound proxy options if any of them is set, otherwise
// the HTTP_PROXY, HTTPS_PROXY and NO_PROXY environment variables.
func outboundProxyFunc(o *Options) func(*http.Request) (*url.URL, error) {
	cfg := httpproxy.FromEnvironment()
	if o.OutboundHttpProxy.IsSet || o.OutboundHttpsProxy.IsSet || o.OutboundNoProxy.IsSet {
		cfg = &httpproxy.Config{
			HTTPProxy:  o.OutboundHttpProxy.Value,
			HTTPSProxy: o.OutboundHttpsProxy.Value,
			NoProxy:    o.OutboundNoProxy.Value,
		}
	}
	proxyURL := cfg.ProxyFunc()
	return func(req *http.Request) (*url.URL, error) {
		return proxyURL(req.URL)
	}
}

// validateOutboundProxyURL returns an error if rawURL is not a usable proxy
// URL. Like HTTP_PROXY, a value without a scheme is an http proxy. The error
// does not include any part of rawURL, which may contain credentials.
func validateOutboundProxyURL(rawURL string) error {
	if rawURL == "" {
		return nil
	}
	if !strings.Contains(rawURL, "://") {
		rawURL = "http://" + rawURL
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		// url.Parse errors can quote parts of the credentials.
		return errors.New("invalid URL (special characters in credentials must be percent-encoded)")
	}
	switch u.Scheme {
	case "http", "https", "socks5", "socks5h":
	default:
		return fmt.Errorf("unsupported proxy scheme %q", u.Scheme)
	}
	if u.Hostname() == "" {
		return errors.New("missing proxy host")
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
