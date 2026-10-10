package envoyconfig

import (
	xds_core_v3 "github.com/cncf/xds/go/xds/core/v3"
	v3 "github.com/cncf/xds/go/xds/type/matcher/v3"
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_listener_v3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_extensions_common_matching_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/common/matching/v3"
	envoy_extensions_filters_http_composite_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/composite/v3"
	envoy_extensions_filters_http_ext_authz_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_authz/v3"
	envoy_extensions_filters_http_ext_proc_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	envoy_extensions_filters_http_header_mutation_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/header_mutation/v3"
	envoy_extensions_filters_http_lua_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/lua/v3"
	envoy_extensions_filters_http_router_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	envoy_extensions_filters_listener_proxy_protocol_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/listener/proxy_protocol/v3"
	envoy_extensions_filters_listener_tls_inspector_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/listener/tls_inspector/v3"
	envoy_extensions_filters_network_http_connection_manager "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	envoy_extensions_filters_network_tcp_proxy_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/tcp_proxy/v3"
	envoy_extensions_matching_common_inputs_network_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/matching/common_inputs/network/v3"
	envoy_extensions_matching_input_matchers_metadata_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/matching/input_matchers/metadata/v3"
	matcherv3 "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	envoy_type_v3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

// ExtAuthzFilter creates an ext authz filter.
func ExtAuthzFilter(grpcClientTimeout *durationpb.Duration) *envoy_extensions_filters_network_http_connection_manager.HttpFilter {
	return &envoy_extensions_filters_network_http_connection_manager.HttpFilter{
		Name: "envoy.filters.http.ext_authz",
		ConfigType: &envoy_extensions_filters_network_http_connection_manager.HttpFilter_TypedConfig{
			TypedConfig: protoutil.NewAny(&envoy_extensions_filters_http_ext_authz_v3.ExtAuthz{
				StatusOnError: &envoy_type_v3.HttpStatus{
					Code: envoy_type_v3.StatusCode_ServiceUnavailable,
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
// The filter is disabled at the HttpFilter level so non-MCP routes never invoke it.
// MCP routes enable it via per-route config overrides.
func ExtProcFilter(grpcClientTimeout *durationpb.Duration) *envoy_config_core_v3.TypedExtensionConfig {
	return &envoy_config_core_v3.TypedExtensionConfig{
		Name: "envoy.filters.http.ext_proc",
		TypedConfig: protoutil.NewAny(&envoy_extensions_filters_http_ext_proc_v3.ExternalProcessor{
			GrpcService: &envoy_config_core_v3.GrpcService{
				Timeout: grpcClientTimeout,
				TargetSpecifier: &envoy_config_core_v3.GrpcService_EnvoyGrpc_{
					EnvoyGrpc: &envoy_config_core_v3.GrpcService_EnvoyGrpc{
						ClusterName: "pomerium-control-plane-grpc",
					},
				},
			},
			MessageTimeout: grpcClientTimeout,
			MetadataOptions: &envoy_extensions_filters_http_ext_proc_v3.MetadataOptions{
				ForwardingNamespaces: &envoy_extensions_filters_http_ext_proc_v3.MetadataOptions_MetadataNamespaces{
					Untyped: []string{
						PerFilterConfigExtAuthzName, // Route context from ext_authz DynamicMetadata
					},
				},
			},
			ProcessingMode: &envoy_extensions_filters_http_ext_proc_v3.ProcessingMode{
				RequestHeaderMode:   envoy_extensions_filters_http_ext_proc_v3.ProcessingMode_SEND,
				RequestBodyMode:     envoy_extensions_filters_http_ext_proc_v3.ProcessingMode_NONE,
				RequestTrailerMode:  envoy_extensions_filters_http_ext_proc_v3.ProcessingMode_SKIP,
				ResponseHeaderMode:  envoy_extensions_filters_http_ext_proc_v3.ProcessingMode_SEND,
				ResponseBodyMode:    envoy_extensions_filters_http_ext_proc_v3.ProcessingMode_NONE,
				ResponseTrailerMode: envoy_extensions_filters_http_ext_proc_v3.ProcessingMode_SKIP,
			},
		}),
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
func HTTPRouterFilter(cfg *config.Config) *envoy_extensions_filters_network_http_connection_manager.HttpFilter {
	return &envoy_extensions_filters_network_http_connection_manager.HttpFilter{
		Name: "envoy.filters.http.router",
		ConfigType: &envoy_extensions_filters_network_http_connection_manager.HttpFilter_TypedConfig{
			TypedConfig: protoutil.NewAny(&envoy_extensions_filters_http_router_v3.Router{
				SuppressEnvoyHeaders: cfg.Options.IsRuntimeFlagSet(config.RuntimeFlagSuppressEnvoyHeaders),
			}),
		},
	}
}

const (
	UseFilterChainMetadataKey          = "com.pomerium.use_filter_chain"
	CompositeFilterChainUpstreamTunnel = "upstream_tunnel"
	CompositeFilterChainMCP            = "mcp"
)

func CompositeFilter(cfg *config.Config) *envoy_extensions_filters_network_http_connection_manager.HttpFilter {
	namedFilterChains := []struct {
		name        string
		filterChain []*envoy_config_core_v3.TypedExtensionConfig
	}{
		{
			name: CompositeFilterChainUpstreamTunnel,
			filterChain: []*envoy_config_core_v3.TypedExtensionConfig{
				UpstreamTunnelSetFilterStateFilter(),
			},
		},
		{
			name: CompositeFilterChainMCP,
			filterChain: []*envoy_config_core_v3.TypedExtensionConfig{
				ExtProcFilter(getGrpcClientTimeout(cfg)),
			},
		},
	}

	matchers := []*v3.Matcher_MatcherList_FieldMatcher{}
	for _, fc := range namedFilterChains {
		matchers = append(matchers, &v3.Matcher_MatcherList_FieldMatcher{
			Predicate: &v3.Matcher_MatcherList_Predicate{
				MatchType: &v3.Matcher_MatcherList_Predicate_SinglePredicate_{
					SinglePredicate: &v3.Matcher_MatcherList_Predicate_SinglePredicate{
						Input: &xds_core_v3.TypedExtensionConfig{
							Name: "envoy.matching.inputs.dynamic_metadata",
							TypedConfig: marshalAny(&envoy_extensions_matching_common_inputs_network_v3.DynamicMetadataInput{
								// match dynamic metadata set by the ext_authz filter
								Filter: "envoy.filters.http.ext_authz",
								Path: []*envoy_extensions_matching_common_inputs_network_v3.DynamicMetadataInput_PathSegment{
									{
										Segment: &envoy_extensions_matching_common_inputs_network_v3.DynamicMetadataInput_PathSegment_Key{
											Key: UseFilterChainMetadataKey,
										},
									},
								},
							}),
						},
						Matcher: &v3.Matcher_MatcherList_Predicate_SinglePredicate_CustomMatch{
							CustomMatch: &xds_core_v3.TypedExtensionConfig{
								Name: "envoy.matching.matchers.metadata_matcher",
								TypedConfig: marshalAny(&envoy_extensions_matching_input_matchers_metadata_v3.Metadata{
									Value: &matcherv3.ValueMatcher{
										MatchPattern: &matcherv3.ValueMatcher_StringMatch{
											StringMatch: &matcherv3.StringMatcher{
												MatchPattern: &matcherv3.StringMatcher_Exact{
													Exact: fc.name,
												},
											},
										},
									},
								}),
							},
						},
					},
				},
			},
			OnMatch: &v3.Matcher_OnMatch{
				OnMatch: &v3.Matcher_OnMatch_Action{
					Action: &xds_core_v3.TypedExtensionConfig{
						Name: "execute-filters",
						TypedConfig: marshalAny(&envoy_extensions_filters_http_composite_v3.ExecuteFilterAction{
							FilterChain: &envoy_extensions_filters_http_composite_v3.FilterChainConfiguration{
								TypedConfig: fc.filterChain,
							},
						}),
					},
				},
			},
		})
	}
	return &envoy_extensions_filters_network_http_connection_manager.HttpFilter{
		Name: "composite-with-matcher",
		ConfigType: &envoy_extensions_filters_network_http_connection_manager.HttpFilter_TypedConfig{
			TypedConfig: marshalAny(&envoy_extensions_common_matching_v3.ExtensionWithMatcher{
				XdsMatcher: &v3.Matcher{
					MatcherType: &v3.Matcher_MatcherList_{
						MatcherList: &v3.Matcher_MatcherList{
							Matchers: matchers,
						},
					},
				},
				ExtensionConfig: &envoy_config_core_v3.TypedExtensionConfig{
					Name:        "envoy.filters.http.composite",
					TypedConfig: marshalAny(&envoy_extensions_filters_http_composite_v3.Composite{}),
				},
			}),
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
