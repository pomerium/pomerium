package envoyconfig

import (
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_listener_v3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_extensions_filters_http_ext_authz_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_authz/v3"
	envoy_extensions_filters_http_ext_proc_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	envoy_extensions_filters_http_header_mutation_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/header_mutation/v3"
	envoy_extensions_filters_http_lua_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/lua/v3"
	envoy_extensions_filters_http_router_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	envoy_extensions_filters_listener_proxy_protocol_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/listener/proxy_protocol/v3"
	envoy_extensions_filters_listener_tls_inspector_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/listener/tls_inspector/v3"
	envoy_extensions_filters_network_http_connection_manager "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	envoy_extensions_filters_network_tcp_proxy_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/tcp_proxy/v3"
	envoy_type_v3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/pomerium/pomerium/pkg/protoutil"
)

// ExtAuthzFilter creates an ext authz filter.
func ExtAuthzFilter(grpcClientTimeout *durationpb.Duration) *envoy_extensions_filters_network_http_connection_manager.HttpFilter {
	return &envoy_extensions_filters_network_http_connection_manager.HttpFilter{
		Name: "envoy.filters.http.ext_authz",
		ConfigType: &envoy_extensions_filters_network_http_connection_manager.HttpFilter_TypedConfig{
			TypedConfig: protoutil.NewAny(&envoy_extensions_filters_http_ext_authz_v3.ExtAuthz{
				StatusOnError: &envoy_type_v3.HttpStatus{
					Code: envoy_type_v3.StatusCode_InternalServerError,
				},
				Services: &envoy_extensions_filters_http_ext_authz_v3.ExtAuthz_GrpcService{
					GrpcService: &envoy_config_core_v3.GrpcService{
						Timeout: grpcClientTimeout,
						TargetSpecifier: &envoy_config_core_v3.GrpcService_EnvoyGrpc_{
							EnvoyGrpc: &envoy_config_core_v3.GrpcService_EnvoyGrpc{
								ClusterName: "pomerium-authorize",
							},
						},
					},
				},
				MetadataContextNamespaces: []string{"com.pomerium.client-certificate-info"},
				TransportApiVersion:       envoy_config_core_v3.ApiVersion_V3,
			}),
		},
	}
}

// ExtProcFilter creates an external processor filter for MCP response interception.
// This filter intercepts responses from upstream servers to handle 401/403 authorization
// challenges for MCP proxy routes. Non-MCP routes disable the filter per-route for efficiency.
func ExtProcFilter(grpcClientTimeout *durationpb.Duration) *envoy_extensions_filters_network_http_connection_manager.HttpFilter {
	return &envoy_extensions_filters_network_http_connection_manager.HttpFilter{
		Name: "envoy.filters.http.ext_proc",
		ConfigType: &envoy_extensions_filters_network_http_connection_manager.HttpFilter_TypedConfig{
			TypedConfig: protoutil.NewAny(&envoy_extensions_filters_http_ext_proc_v3.ExternalProcessor{
				GrpcService: &envoy_config_core_v3.GrpcService{
					Timeout: grpcClientTimeout,
					TargetSpecifier: &envoy_config_core_v3.GrpcService_EnvoyGrpc_{
						EnvoyGrpc: &envoy_config_core_v3.GrpcService_EnvoyGrpc{
							ClusterName: "pomerium-control-plane-grpc",
						},
					},
				},
				ProcessingMode: &envoy_extensions_filters_http_ext_proc_v3.ProcessingMode{
					// Default: SEND headers for processing. Non-MCP routes disable the filter per-route
					// for efficiency (Envoy completely bypasses the filter when disabled).
					RequestHeaderMode:   envoy_extensions_filters_http_ext_proc_v3.ProcessingMode_SEND,
					RequestBodyMode:     envoy_extensions_filters_http_ext_proc_v3.ProcessingMode_NONE,
					RequestTrailerMode:  envoy_extensions_filters_http_ext_proc_v3.ProcessingMode_SKIP,
					ResponseHeaderMode:  envoy_extensions_filters_http_ext_proc_v3.ProcessingMode_SEND,
					ResponseBodyMode:    envoy_extensions_filters_http_ext_proc_v3.ProcessingMode_NONE,
					ResponseTrailerMode: envoy_extensions_filters_http_ext_proc_v3.ProcessingMode_SKIP,
				},
				MessageTimeout: grpcClientTimeout,
				// Configure metadata namespaces
				MetadataOptions: &envoy_extensions_filters_http_ext_proc_v3.MetadataOptions{
					// Forward metadata from stream info to ext_proc service.
					// Note: ext_authz stores its DynamicMetadata under "envoy.filters.http.ext_authz"
					// namespace, so we must forward that namespace to receive route context.
					ForwardingNamespaces: &envoy_extensions_filters_http_ext_proc_v3.MetadataOptions_MetadataNamespaces{
						Untyped: []string{
							"envoy.filters.http.ext_authz",         // Route context from ext_authz DynamicMetadata
							"com.pomerium.client-certificate-info", // Client cert metadata from Lua
						},
					},
				},
			}),
		},
	}
}

// HTTPConnectionManagerFilter creates a new HTTP connection manager filter.
func (b *Builder) HTTPConnectionManagerFilter(
	httpConnectionManager *envoy_extensions_filters_network_http_connection_manager.HttpConnectionManager,
) *envoy_config_listener_v3.Filter {
	b.applyGlobalHTTPConnectionManagerOptions(httpConnectionManager)
	return &envoy_config_listener_v3.Filter{
		Name: "envoy.filters.network.http_connection_manager",
		ConfigType: &envoy_config_listener_v3.Filter_TypedConfig{
			TypedConfig: protoutil.NewAny(httpConnectionManager),
		},
	}
}

// HTTPHeaderMutationsFilter creates a new HTTP header mutations filter.
func HTTPHeaderMutationsFilter(mutation *envoy_extensions_filters_http_header_mutation_v3.HeaderMutation) *envoy_extensions_filters_network_http_connection_manager.HttpFilter {
	return &envoy_extensions_filters_network_http_connection_manager.HttpFilter{
		Name: "envoy.filters.http.header_mutation",
		ConfigType: &envoy_extensions_filters_network_http_connection_manager.HttpFilter_TypedConfig{
			TypedConfig: protoutil.NewAny(mutation),
		},
	}
}

// HTTPRouterFilter creates a new HTTP router filter.
func HTTPRouterFilter() *envoy_extensions_filters_network_http_connection_manager.HttpFilter {
	return &envoy_extensions_filters_network_http_connection_manager.HttpFilter{
		Name: "envoy.filters.http.router",
		ConfigType: &envoy_extensions_filters_network_http_connection_manager.HttpFilter_TypedConfig{
			TypedConfig: protoutil.NewAny(&envoy_extensions_filters_http_router_v3.Router{}),
		},
	}
}

// LuaFilter creates a lua HTTP filter.
func LuaFilter(defaultSourceCode string) *envoy_extensions_filters_network_http_connection_manager.HttpFilter {
	return &envoy_extensions_filters_network_http_connection_manager.HttpFilter{
		Name: "envoy.filters.http.lua",
		ConfigType: &envoy_extensions_filters_network_http_connection_manager.HttpFilter_TypedConfig{
			TypedConfig: protoutil.NewAny(&envoy_extensions_filters_http_lua_v3.Lua{
				DefaultSourceCode: &envoy_config_core_v3.DataSource{
					Specifier: &envoy_config_core_v3.DataSource_InlineString{
						InlineString: defaultSourceCode,
					},
				},
			}),
		},
	}
}

// ProxyProtocolFilter creates a new Proxy Protocol filter.
func ProxyProtocolFilter() *envoy_config_listener_v3.ListenerFilter {
	return &envoy_config_listener_v3.ListenerFilter{
		Name: "envoy.filters.listener.proxy_protocol",
		ConfigType: &envoy_config_listener_v3.ListenerFilter_TypedConfig{
			TypedConfig: protoutil.NewAny(&envoy_extensions_filters_listener_proxy_protocol_v3.ProxyProtocol{}),
		},
	}
}

// TCPProxyFilter creates a new TCP Proxy filter.
func TCPProxyFilter(clusterName string) *envoy_config_listener_v3.Filter {
	return &envoy_config_listener_v3.Filter{
		Name: "tcp_proxy",
		ConfigType: &envoy_config_listener_v3.Filter_TypedConfig{
			TypedConfig: protoutil.NewAny(&envoy_extensions_filters_network_tcp_proxy_v3.TcpProxy{
				StatPrefix: "acme_tls_alpn",
				ClusterSpecifier: &envoy_extensions_filters_network_tcp_proxy_v3.TcpProxy_Cluster{
					Cluster: clusterName,
				},
			}),
		},
	}
}

// TLSInspectorFilter creates a new TLS inspector filter.
func TLSInspectorFilter() *envoy_config_listener_v3.ListenerFilter {
	return &envoy_config_listener_v3.ListenerFilter{
		Name: "tls_inspector",
		ConfigType: &envoy_config_listener_v3.ListenerFilter_TypedConfig{
			TypedConfig: protoutil.NewAny(&envoy_extensions_filters_listener_tls_inspector_v3.TlsInspector{}),
		},
	}
}
