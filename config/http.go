package config

import (
	"context"
	"crypto/tls"
	"net/http"
	"sync/atomic"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/tripper"
	"github.com/pomerium/pomerium/pkg/cryptutil"
)

type httpTransport struct {
	underlying *http.Transport
	transport  atomic.Value
}

// NewHTTPTransport creates a new http transport. If CA or CAFile is set, the transport will
// add the CA to system cert pool.
func NewHTTPTransport(src Source) http.RoundTripper {
	t := new(httpTransport)
	t.underlying, _ = http.DefaultTransport.(*http.Transport)
	src.OnConfigChange(func(cfg *Config) {
		t.update(cfg.Options)
	})
	t.update(src.GetConfig().Options)
	return t
}

func (t *httpTransport) update(options *Options) {
	nt := new(http.Transport)
	if t.underlying != nil {
		nt = t.underlying.Clone()
	}
	if options.CA != "" || options.CAFile != "" {
		rootCAs, err := cryptutil.GetCertPool(options.CA, options.CAFile)
		if err == nil {
			nt.TLSClientConfig = &tls.Config{
				RootCAs:    rootCAs,
				MinVersion: tls.VersionTLS12,
			}
		} else {
			log.Error(context.TODO()).Err(err).Msg("config: error getting cert pool")
		}
	}
	t.transport.Store(nt)
}

// RoundTrip executes an HTTP request.
func (t *httpTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return t.transport.Load().(http.RoundTripper).RoundTrip(req)
}

// Clone returns a clone of the transport.
func (t *httpTransport) Clone() *http.Transport {
	return t.transport.Load().(*http.Transport).Clone()
}

// NewPolicyHTTPTransport creates a new http RoundTripper for a policy.
func NewPolicyHTTPTransport(options *Options, policy *Policy) http.RoundTripper {
	transport := http.DefaultTransport.(interface {
		Clone() *http.Transport
	}).Clone()
	c := tripper.NewChain()

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
			log.Error(context.TODO()).Err(err).Msg("config: error getting ca cert pool")
		}
	}

	if policy.TLSCustomCA != "" || policy.TLSCustomCAFile != "" {
		rootCAs, err := cryptutil.GetCertPool(policy.TLSCustomCA, policy.TLSCustomCAFile)
		if err == nil {
			tlsClientConfig.RootCAs = rootCAs
			tlsClientConfig.MinVersion = tls.VersionTLS12
			isCustomClientConfig = true
		} else {
			log.Error(context.TODO()).Err(err).Msg("config: error getting custom ca cert pool")
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

	// We avoid setting a custom client config unless we have to as
	// if TLSClientConfig is nil, the default configuration is used.
	if isCustomClientConfig {
		transport.TLSClientConfig = &tlsClientConfig
	}
	return c.Then(transport)
}
