package controlplane

import (
	"fmt"
	"time"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_extensions_filters_http_ext_authz_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_authz/v3"
	envoy_extensions_filters_http_lua_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/lua/v3"
	envoy_http_connection_manager "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	envoy_type_v3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/pomerium/pomerium/config"
)

func getHTTPConnectionManagerFilters(options *config.Options, tlsDomain string) []*envoy_http_connection_manager.HttpFilter {
	fs := []*envoy_http_connection_manager.HttpFilter{
		getRemoveImpersonateHeadersFilter(),
		getExtAuthZFilter(options),
		getExtAuthZSetCookieFilter(),
		getCleanUpstreamFilter(),
	}

	if tlsDomain != "" && tlsDomain != "*" {
		fs = append(fs, getFixMisdirectedFilter(tlsDomain))
	}

	fs = append(fs, &envoy_http_connection_manager.HttpFilter{
		Name: wellknown.Router,
	})

	return fs
}

func getRemoveImpersonateHeadersFilter() *envoy_http_connection_manager.HttpFilter {
	data := marshalAny(&envoy_extensions_filters_http_lua_v3.Lua{
		InlineCode: luascripts.RemoveImpersonateHeaders,
	})
	return &envoy_http_connection_manager.HttpFilter{
		Name: wellknown.Lua,
		ConfigType: &envoy_http_connection_manager.HttpFilter_TypedConfig{
			TypedConfig: data,
		},
	}
}

func getExtAuthZFilter(options *config.Options) *envoy_http_connection_manager.HttpFilter {
	var grpcClientTimeout *durationpb.Duration
	if options.GRPCClientTimeout != 0 {
		grpcClientTimeout = durationpb.New(options.GRPCClientTimeout)
	} else {
		grpcClientTimeout = durationpb.New(30 * time.Second)
	}
	data := marshalAny(&envoy_extensions_filters_http_ext_authz_v3.ExtAuthz{
		StatusOnError: &envoy_type_v3.HttpStatus{
			Code: envoy_type_v3.StatusCode_InternalServerError,
		},
		Services: &envoy_extensions_filters_http_ext_authz_v3.ExtAuthz_GrpcService{
			GrpcService: &envoy_config_core_v3.GrpcService{
				Timeout: grpcClientTimeout,
				TargetSpecifier: &envoy_config_core_v3.GrpcService_EnvoyGrpc_{
					EnvoyGrpc: &envoy_config_core_v3.GrpcService_EnvoyGrpc{
						ClusterName: options.GetAuthorizeURL().Host,
					},
				},
			},
		},
		IncludePeerCertificate: true,
	})
	return &envoy_http_connection_manager.HttpFilter{
		Name: wellknown.HTTPExternalAuthorization,
		ConfigType: &envoy_http_connection_manager.HttpFilter_TypedConfig{
			TypedConfig: data,
		},
	}
}

func getExtAuthZSetCookieFilter() *envoy_http_connection_manager.HttpFilter {
	data := marshalAny(&envoy_extensions_filters_http_lua_v3.Lua{
		InlineCode: luascripts.ExtAuthzSetCookie,
	})
	return &envoy_http_connection_manager.HttpFilter{
		Name: wellknown.Lua,
		ConfigType: &envoy_http_connection_manager.HttpFilter_TypedConfig{
			TypedConfig: data,
		},
	}
}

func getCleanUpstreamFilter() *envoy_http_connection_manager.HttpFilter {
	data := marshalAny(&envoy_extensions_filters_http_lua_v3.Lua{
		InlineCode: luascripts.CleanUpstream,
	})
	return &envoy_http_connection_manager.HttpFilter{
		Name: wellknown.Lua,
		ConfigType: &envoy_http_connection_manager.HttpFilter_TypedConfig{
			TypedConfig: data,
		},
	}
}

func getFixMisdirectedFilter(fqdn string) *envoy_http_connection_manager.HttpFilter {
	// based on https://github.com/projectcontour/contour/pull/2483/files#diff-7b5eca045986ae5cb249a53591b132b2db720095fa9fa24715178f660383b6c6R303
	code := fmt.Sprintf(luascripts.FixMisdirected, fqdn)
	data := marshalAny(&envoy_extensions_filters_http_lua_v3.Lua{
		InlineCode: code,
	})
	return &envoy_http_connection_manager.HttpFilter{
		Name: wellknown.Lua,
		ConfigType: &envoy_http_connection_manager.HttpFilter_TypedConfig{
			TypedConfig: data,
		},
	}
}
