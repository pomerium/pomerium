package envoyconfig

import (
	"testing"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_extensions_http_header_formatters_preserve_case_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/http/header_formatters/preserve_case/v3"
	envoy_extensions_upstreams_http_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/upstreams/http/v3"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/testing/protocmp"
)

func Test_buildUpstreamProtocolOptions(t *testing.T) {
	t.Parallel()

	assert.Empty(t,
		cmp.Diff(&envoy_extensions_upstreams_http_v3.HttpProtocolOptions{
			UpstreamProtocolOptions: &envoy_extensions_upstreams_http_v3.HttpProtocolOptions_ExplicitHttpConfig_{
				ExplicitHttpConfig: &envoy_extensions_upstreams_http_v3.HttpProtocolOptions_ExplicitHttpConfig{
					ProtocolConfig: &envoy_extensions_upstreams_http_v3.HttpProtocolOptions_ExplicitHttpConfig_HttpProtocolOptions{
						HttpProtocolOptions: &envoy_config_core_v3.Http1ProtocolOptions{
							HeaderKeyFormat: &envoy_config_core_v3.Http1ProtocolOptions_HeaderKeyFormat{
								HeaderFormat: &envoy_config_core_v3.Http1ProtocolOptions_HeaderKeyFormat_StatefulFormatter{
									StatefulFormatter: &envoy_config_core_v3.TypedExtensionConfig{
										Name:        "preserve_case",
										TypedConfig: marshalAny(&envoy_extensions_http_header_formatters_preserve_case_v3.PreserveCaseFormatterConfig{}),
									},
								},
							},
						},
					},
				},
			},
		}, buildUpstreamProtocolOptions(nil, upstreamProtocolHTTP1), protocmp.Transform()))
}
