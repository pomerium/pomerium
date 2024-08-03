package envoyconfig

import (
	"testing"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_extensions_upstreams_http_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/upstreams/http/v3"

	"github.com/pomerium/pomerium/internal/testutil"
)

func TestBuildUpstreamProtocolOptions(t *testing.T) {
	t.Parallel()

	var (
		explicitH2 = &envoy_extensions_upstreams_http_v3.HttpProtocolOptions{
			UpstreamProtocolOptions: &envoy_extensions_upstreams_http_v3.HttpProtocolOptions_ExplicitHttpConfig_{
				ExplicitHttpConfig: &envoy_extensions_upstreams_http_v3.HttpProtocolOptions_ExplicitHttpConfig{
					ProtocolConfig: &envoy_extensions_upstreams_http_v3.HttpProtocolOptions_ExplicitHttpConfig_Http2ProtocolOptions{
						Http2ProtocolOptions: http2ProtocolOptions,
					},
				},
			},
		}
		explicitH2Keepalive = &envoy_extensions_upstreams_http_v3.HttpProtocolOptions{
			UpstreamProtocolOptions: &envoy_extensions_upstreams_http_v3.HttpProtocolOptions_ExplicitHttpConfig_{
				ExplicitHttpConfig: &envoy_extensions_upstreams_http_v3.HttpProtocolOptions_ExplicitHttpConfig{
					ProtocolConfig: &envoy_extensions_upstreams_http_v3.HttpProtocolOptions_ExplicitHttpConfig_Http2ProtocolOptions{
						Http2ProtocolOptions: http2ProtocolOptionsWithKeepalive,
					},
				},
			},
		}
		explicitH1 = &envoy_extensions_upstreams_http_v3.HttpProtocolOptions{
			UpstreamProtocolOptions: &envoy_extensions_upstreams_http_v3.HttpProtocolOptions_ExplicitHttpConfig_{
				ExplicitHttpConfig: &envoy_extensions_upstreams_http_v3.HttpProtocolOptions_ExplicitHttpConfig{
					ProtocolConfig: &envoy_extensions_upstreams_http_v3.HttpProtocolOptions_ExplicitHttpConfig_HttpProtocolOptions{
						HttpProtocolOptions: http1ProtocolOptions,
					},
				},
			},
		}
		explicitH1Keepalive = &envoy_extensions_upstreams_http_v3.HttpProtocolOptions{
			UpstreamProtocolOptions: &envoy_extensions_upstreams_http_v3.HttpProtocolOptions_ExplicitHttpConfig_{
				ExplicitHttpConfig: &envoy_extensions_upstreams_http_v3.HttpProtocolOptions_ExplicitHttpConfig{
					ProtocolConfig: &envoy_extensions_upstreams_http_v3.HttpProtocolOptions_ExplicitHttpConfig_HttpProtocolOptions{
						HttpProtocolOptions: http1ProtocolOptions,
					},
				},
			},
		}
		auto = &envoy_extensions_upstreams_http_v3.HttpProtocolOptions{
			UpstreamProtocolOptions: &envoy_extensions_upstreams_http_v3.HttpProtocolOptions_AutoConfig{
				AutoConfig: &envoy_extensions_upstreams_http_v3.HttpProtocolOptions_AutoHttpConfig{
					HttpProtocolOptions:  http1ProtocolOptions,
					Http2ProtocolOptions: http2ProtocolOptions,
				},
			},
		}
		autoKeepalive = &envoy_extensions_upstreams_http_v3.HttpProtocolOptions{
			UpstreamProtocolOptions: &envoy_extensions_upstreams_http_v3.HttpProtocolOptions_AutoConfig{
				AutoConfig: &envoy_extensions_upstreams_http_v3.HttpProtocolOptions_AutoHttpConfig{
					HttpProtocolOptions:  http1ProtocolOptions,
					Http2ProtocolOptions: http2ProtocolOptionsWithKeepalive,
				},
			},
		}
	)
	cases := []struct {
		endpoints []string
		protocol  upstreamProtocolConfig
		keepalive bool
		expected  *envoy_extensions_upstreams_http_v3.HttpProtocolOptions
	}{
		{[]string{"https://foo", "https://bar"}, upstreamProtocolHTTP1, false, explicitH1},
		{[]string{"https://foo", "https://bar"}, upstreamProtocolHTTP1, true, explicitH1Keepalive},
		{[]string{"http://foo", "https://bar"}, upstreamProtocolHTTP1, false, explicitH1},
		{[]string{"http://foo", "https://bar"}, upstreamProtocolHTTP1, true, explicitH1Keepalive},
		{[]string{"http://foo", "http://bar"}, upstreamProtocolHTTP1, false, explicitH1},
		{[]string{"http://foo", "http://bar"}, upstreamProtocolHTTP1, true, explicitH1Keepalive},

		{[]string{"https://foo", "https://bar"}, upstreamProtocolHTTP2, false, explicitH2},
		{[]string{"https://foo", "https://bar"}, upstreamProtocolHTTP2, true, explicitH2Keepalive},
		{[]string{"http://foo", "https://bar"}, upstreamProtocolHTTP2, false, explicitH2},
		{[]string{"http://foo", "https://bar"}, upstreamProtocolHTTP2, true, explicitH2Keepalive},
		{[]string{"http://foo", "http://bar"}, upstreamProtocolHTTP2, false, explicitH2},
		{[]string{"http://foo", "http://bar"}, upstreamProtocolHTTP2, true, explicitH2Keepalive},

		{[]string{"https://foo", "https://bar"}, upstreamProtocolAuto, false, auto},
		{[]string{"https://foo", "https://bar"}, upstreamProtocolAuto, true, autoKeepalive},
		{[]string{"http://foo", "https://bar"}, upstreamProtocolAuto, false, explicitH1},
		{[]string{"http://foo", "https://bar"}, upstreamProtocolAuto, true, explicitH1Keepalive},
		{[]string{"http://foo", "http://bar"}, upstreamProtocolAuto, false, explicitH1},
		{[]string{"http://foo", "http://bar"}, upstreamProtocolAuto, true, explicitH1Keepalive},

		{[]string{"h2c://foo", "http://bar"}, upstreamProtocolAuto, false, explicitH1},
		{[]string{"h2c://foo", "http://bar"}, upstreamProtocolAuto, true, explicitH1Keepalive},
		{[]string{"h2c://foo", "https://bar"}, upstreamProtocolAuto, false, explicitH1},
		{[]string{"h2c://foo", "https://bar"}, upstreamProtocolAuto, true, explicitH1Keepalive},
		{[]string{"h2c://foo", "h2c://bar"}, upstreamProtocolAuto, false, explicitH2},
		{[]string{"h2c://foo", "h2c://bar"}, upstreamProtocolAuto, true, explicitH2Keepalive},
	}

	for _, tc := range cases {
		t.Run("", func(t *testing.T) {
			endpoints := []Endpoint{}
			for _, e := range tc.endpoints {
				endpoint := Endpoint{url: *mustParseURL(t, e)}
				// match logic from buildInternalTransportSocket
				if endpoint.url.Scheme == "https" {
					// buildUpstreamProtocolOptions only checks for the presence of
					// transportSocket, and does not inspect any of its contents
					endpoint.transportSocket = &envoy_config_core_v3.TransportSocket{}
				}
				endpoints = append(endpoints, endpoint)
			}
			testutil.AssertProtoEqual(t, tc.expected, buildUpstreamProtocolOptions(endpoints, tc.protocol, Keepalive(tc.keepalive)))
		})
	}
}
