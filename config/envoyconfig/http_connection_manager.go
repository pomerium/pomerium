package envoyconfig

import (
	"fmt"
	"strings"

	envoy_config_accesslog_v3 "github.com/envoyproxy/go-control-plane/envoy/config/accesslog/v3"
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoy_http_connection_manager "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/ui"
)

func (b *Builder) buildVirtualHost(
	options *config.Options,
	name string,
	host string,
) (*envoy_config_route_v3.VirtualHost, error) {
	vh := &envoy_config_route_v3.VirtualHost{
		Name:    name,
		Domains: []string{host},
	}

	// if we're stripping the port from incoming requests
	// and this host doesn't have a port or wildcard in it
	// then we will add :* to match on any port
	if options.IsRuntimeFlagSet(config.RuntimeFlagMatchAnyIncomingPort) &&
		!strings.Contains(host, "*") &&
		!config.HasPort(host) {
		vh.Domains = append(vh.Domains, host+":*")
	}

	// these routes match /.pomerium/... and similar paths
	rs, err := b.buildPomeriumHTTPRoutes(options, host)
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
) (*envoy_http_connection_manager.LocalReplyConfig, error) {
	// add global headers for HSTS headers (#2110)
	var headers []*envoy_config_core_v3.HeaderValueOption
	// if we're the proxy or authenticate service, add our global headers
	if config.IsProxy(options.Services) || config.IsAuthenticate(options.Services) {
		headers = toEnvoyHeaders(options.GetSetResponseHeaders())
	}

	data := make(map[string]any)
	httputil.AddBrandingOptionsToMap(data, options.BrandingOptions)
	for k, v := range data {
		// Escape any % signs in the branding options data, as Envoy will
		// interpret the page output as a substitution format string.
		if s, ok := v.(string); ok {
			data[k] = strings.ReplaceAll(s, "%", "%%")
		}
	}
	data["status"] = "%RESPONSE_CODE%"
	data["statusText"] = "%RESPONSE_CODE_DETAILS%"
	data["requestId"] = "%STREAM_ID%"
	data["responseFlags"] = "%RESPONSE_FLAGS%"

	bs, err := ui.RenderPage("Error", "Error", data)
	if err != nil {
		return nil, fmt.Errorf("error rendering error page for local reply: %w", err)
	}

	return &envoy_http_connection_manager.LocalReplyConfig{
		Mappers: []*envoy_http_connection_manager.ResponseMapper{{
			Filter: &envoy_config_accesslog_v3.AccessLogFilter{
				FilterSpecifier: &envoy_config_accesslog_v3.AccessLogFilter_ResponseFlagFilter{
					ResponseFlagFilter: &envoy_config_accesslog_v3.ResponseFlagFilter{
						Flags: []string{
							"DC",
							"DF",
							"DI",
							"DO",
							"DPE",
							"DT",
							"FI",
							"IH",
							"LH",
							"LR",
							"NC",
							"NFCF",
							"NR",
							"OM",
							"RFCF",
							"RL",
							"RLSE",
							"SI",
							// "UAEX", // excluded because this response is handled in the authorize service
							"UC",
							"UF",
							"UH",
							"UMSDR",
							"UO",
							"UPE",
							"UR",
							"URX",
							"UT",
						},
					},
				},
			},
			BodyFormatOverride: &envoy_config_core_v3.SubstitutionFormatString{
				ContentType: "text/html; charset=UTF-8",
				Format: &envoy_config_core_v3.SubstitutionFormatString_TextFormatSource{
					TextFormatSource: &envoy_config_core_v3.DataSource{
						Specifier: &envoy_config_core_v3.DataSource_InlineBytes{
							InlineBytes: bs,
						},
					},
				},
			},
			HeadersToAdd: headers,
		}},
	}, nil
}
