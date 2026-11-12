package outbound

import (
	"fmt"

	"golang.org/x/net/http/httpproxy"

	"github.com/pomerium/pomerium/pkg/nullable"
)

// ProxyOptions are the outbound proxy options: outbound_http_proxy,
// outbound_https_proxy and outbound_no_proxy. An option set to "" is set.
type ProxyOptions struct {
	HTTPProxy  nullable.Value[string]
	HTTPSProxy nullable.Value[string]
	NoProxy    nullable.Value[string]
}

// ProxySettings returns the proxy settings for Pomerium's own outbound HTTP
// requests: the options if any of them is set, otherwise the HTTP_PROXY,
// HTTPS_PROXY and NO_PROXY environment variables. If a proxy URL option is
// not a valid proxy URL, ProxyErr is an error naming the option, but not its
// value.
func ProxySettings(o ProxyOptions) Settings {
	cfg, err := proxyConfig(o)
	return Settings{Proxy: cfg, ProxyErr: err}
}

// proxyConfig returns the proxy configuration of [ProxySettings], and the
// error for an invalid proxy URL option.
func proxyConfig(o ProxyOptions) (httpproxy.Config, error) {
	if !o.HTTPProxy.IsSet && !o.HTTPSProxy.IsSet && !o.NoProxy.IsSet {
		return *httpproxy.FromEnvironment(), nil
	}
	return httpproxy.Config{
		HTTPProxy:  o.HTTPProxy.Value,
		HTTPSProxy: o.HTTPSProxy.Value,
		NoProxy:    o.NoProxy.Value,
	}, validateProxyURLOptions(o)
}

// ValidateProxyOptions returns an error naming the first invalid option, but
// not its value.
func ValidateProxyOptions(o ProxyOptions) error {
	if err := validateProxyURLOptions(o); err != nil {
		return err
	}
	if err := validateNoProxy(o.NoProxy.Or("")); err != nil {
		return fmt.Errorf("bad outbound_no_proxy: %w", err)
	}
	return nil
}

// validateProxyURLOptions returns an error naming outbound_http_proxy or
// outbound_https_proxy, but not its value, if it is not a usable proxy URL.
func validateProxyURLOptions(o ProxyOptions) error {
	if err := validateProxyURL(o.HTTPProxy.Or("")); err != nil {
		return fmt.Errorf("bad outbound_http_proxy: %w", err)
	}
	if err := validateProxyURL(o.HTTPSProxy.Or("")); err != nil {
		return fmt.Errorf("bad outbound_https_proxy: %w", err)
	}
	return nil
}
