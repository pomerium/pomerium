package controlplane

import (
	"encoding/json"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_extensions_upstreams_http_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/upstreams/http/v3"

	"github.com/pomerium/pomerium/internal/log"
)

func buildUpstreamProtocolOptions(endpoints []Endpoint, forceHTTP2 bool) *envoy_extensions_upstreams_http_v3.HttpProtocolOptions {
	// if forcing http/2, use that explicitly
	if forceHTTP2 {
		return &envoy_extensions_upstreams_http_v3.HttpProtocolOptions{
			UpstreamProtocolOptions: &envoy_extensions_upstreams_http_v3.HttpProtocolOptions_ExplicitHttpConfig_{
				ExplicitHttpConfig: &envoy_extensions_upstreams_http_v3.HttpProtocolOptions_ExplicitHttpConfig{
					ProtocolConfig: &envoy_extensions_upstreams_http_v3.HttpProtocolOptions_ExplicitHttpConfig_Http2ProtocolOptions{
						Http2ProtocolOptions: &envoy_config_core_v3.Http2ProtocolOptions{
							AllowConnect: true,
						},
					},
				},
			},
		}
	}

	// when using TLS use ALPN auto config
	tlsCount := 0
	for _, e := range endpoints {
		if e.transportSocket != nil {
			tlsCount++
		}
	}
	if tlsCount > 0 && tlsCount == len(endpoints) {
		for _, e := range endpoints {
			bs, _ := json.Marshal(e.transportSocket)
			log.Info().
				Str("url", e.url.String()).
				Str("endpoints", string(bs)).
				Msg("<<<USE AUTO>>>")
		}
		return &envoy_extensions_upstreams_http_v3.HttpProtocolOptions{
			UpstreamProtocolOptions: &envoy_extensions_upstreams_http_v3.HttpProtocolOptions_AutoConfig{
				AutoConfig: &envoy_extensions_upstreams_http_v3.HttpProtocolOptions_AutoHttpConfig{},
			},
		}
	}

	// otherwise only use http/1.1
	return &envoy_extensions_upstreams_http_v3.HttpProtocolOptions{
		UpstreamProtocolOptions: &envoy_extensions_upstreams_http_v3.HttpProtocolOptions_ExplicitHttpConfig_{
			ExplicitHttpConfig: &envoy_extensions_upstreams_http_v3.HttpProtocolOptions_ExplicitHttpConfig{
				ProtocolConfig: &envoy_extensions_upstreams_http_v3.HttpProtocolOptions_ExplicitHttpConfig_HttpProtocolOptions{
					HttpProtocolOptions: &envoy_config_core_v3.Http1ProtocolOptions{},
				},
			},
		},
	}
}
