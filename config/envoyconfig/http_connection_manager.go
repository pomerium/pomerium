package envoyconfig

import (
	envoy_config_accesslog_v3 "github.com/envoyproxy/go-control-plane/envoy/config/accesslog/v3"
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoy_http_connection_manager "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"

	"github.com/pomerium/pomerium/config"
)

func (b *Builder) buildVirtualHost(
	options *config.Options,
	name string,
	host string,
	requireStrictTransportSecurity bool,
) (*envoy_config_route_v3.VirtualHost, error) {
	vh := &envoy_config_route_v3.VirtualHost{
		Name:    name,
		Domains: []string{host},
	}

	// these routes match /.pomerium/... and similar paths
	rs, err := b.buildPomeriumHTTPRoutes(options, host, requireStrictTransportSecurity)
	if err != nil {
		return nil, err
	}
	vh.Routes = append(vh.Routes, rs...)

	return vh, nil
}

// buildLocalReplyConfig builds the local reply config: the config used to modify "local" replies, that is replies
// coming directly from envoy
func (b *Builder) buildLocalReplyConfig(
	options *config.Options,
	requireStrictTransportSecurity bool,
) *envoy_http_connection_manager.LocalReplyConfig {
	// add global headers for HSTS headers (#2110)
	var headers []*envoy_config_core_v3.HeaderValueOption
	// if we're the proxy or authenticate service, add our global headers
	if config.IsProxy(options.Services) || config.IsAuthenticate(options.Services) {
		headers = toEnvoyHeaders(options.GetSetResponseHeaders(requireStrictTransportSecurity))
	}

	return &envoy_http_connection_manager.LocalReplyConfig{
		Mappers: []*envoy_http_connection_manager.ResponseMapper{{
			Filter: &envoy_config_accesslog_v3.AccessLogFilter{
				FilterSpecifier: &envoy_config_accesslog_v3.AccessLogFilter_ResponseFlagFilter{
					ResponseFlagFilter: &envoy_config_accesslog_v3.ResponseFlagFilter{},
				},
			},
			HeadersToAdd: headers,
		}},
	}
}
