package controlplane

import (
	"encoding/base64"
	"sort"
	"time"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_listener_v3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_config_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoy_extensions_filters_http_ext_authz_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_authz/v3"
	envoy_extensions_filters_http_lua_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/lua/v3"
	envoy_http_connection_manager "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	envoy_extensions_transport_sockets_tls_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	envoy_type_v3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/any"
	"github.com/golang/protobuf/ptypes/wrappers"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/cryptutil"
	"github.com/pomerium/pomerium/internal/log"
)

var disableExtAuthz *any.Any

func init() {
	disableExtAuthz, _ = ptypes.MarshalAny(&envoy_extensions_filters_http_ext_authz_v3.ExtAuthzPerRoute{
		Override: &envoy_extensions_filters_http_ext_authz_v3.ExtAuthzPerRoute_Disabled{
			Disabled: true,
		},
	})
}

func buildListeners(options *config.Options) []*envoy_config_listener_v3.Listener {
	var listeners []*envoy_config_listener_v3.Listener

	if config.IsAuthenticate(options.Services) || config.IsProxy(options.Services) {
		listeners = append(listeners, buildMainListener(options))
	}

	if config.IsAuthorize(options.Services) || config.IsCache(options.Services) {
		listeners = append(listeners, buildGRPCListener(options))
	}

	return listeners
}

func buildMainListener(options *config.Options) *envoy_config_listener_v3.Listener {
	if options.InsecureServer {
		filter := buildMainHTTPConnectionManagerFilter(options,
			getAllRouteableDomains(options, options.Addr))

		return &envoy_config_listener_v3.Listener{
			Name:    "http-ingress",
			Address: buildAddress(options.Addr, 80),
			FilterChains: []*envoy_config_listener_v3.FilterChain{{
				Filters: []*envoy_config_listener_v3.Filter{
					filter,
				},
			}},
		}
	}

	tlsInspectorCfg, _ := ptypes.MarshalAny(new(emptypb.Empty))
	li := &envoy_config_listener_v3.Listener{
		Name:    "https-ingress",
		Address: buildAddress(options.Addr, 443),
		ListenerFilters: []*envoy_config_listener_v3.ListenerFilter{{
			Name: "envoy.filters.listener.tls_inspector",
			ConfigType: &envoy_config_listener_v3.ListenerFilter_TypedConfig{
				TypedConfig: tlsInspectorCfg,
			},
		}},
		FilterChains: buildFilterChains(options, options.Addr,
			func(tlsDomain string, httpDomains []string) *envoy_config_listener_v3.FilterChain {
				filter := buildMainHTTPConnectionManagerFilter(options, httpDomains)
				filterChain := &envoy_config_listener_v3.FilterChain{
					Filters: []*envoy_config_listener_v3.Filter{filter},
				}
				if tlsDomain != "*" {
					filterChain.FilterChainMatch = &envoy_config_listener_v3.FilterChainMatch{
						ServerNames: []string{tlsDomain},
					}
				}
				tlsContext := buildDownstreamTLSContext(options, tlsDomain)
				if tlsContext != nil {
					tlsConfig, _ := ptypes.MarshalAny(tlsContext)
					filterChain.TransportSocket = &envoy_config_core_v3.TransportSocket{
						Name: "tls",
						ConfigType: &envoy_config_core_v3.TransportSocket_TypedConfig{
							TypedConfig: tlsConfig,
						},
					}
				}
				return filterChain
			}),
	}
	return li
}

func buildFilterChains(
	options *config.Options, addr string,
	callback func(tlsDomain string, httpDomains []string) *envoy_config_listener_v3.FilterChain,
) []*envoy_config_listener_v3.FilterChain {
	allDomains := getAllRouteableDomains(options, addr)
	var chains []*envoy_config_listener_v3.FilterChain
	for _, domain := range allDomains {
		// first we match on SNI
		chains = append(chains, callback(domain, allDomains))
	}
	// if there are no SNI matches we match on HTTP host
	chains = append(chains, callback("*", allDomains))
	return chains
}

func buildMainHTTPConnectionManagerFilter(options *config.Options, domains []string) *envoy_config_listener_v3.Filter {
	var virtualHosts []*envoy_config_route_v3.VirtualHost
	for _, domain := range domains {
		vh := &envoy_config_route_v3.VirtualHost{
			Name:    domain,
			Domains: []string{domain},
		}

		if options.Addr == options.GRPCAddr {
			// if this is a gRPC service domain and we're supposed to handle that, add those routes
			if (config.IsAuthorize(options.Services) && domain == options.GetAuthorizeURL().Host) ||
				(config.IsCache(options.Services) && domain == options.GetCacheURL().Host) {
				vh.Routes = append(vh.Routes, buildGRPCRoutes()...)
			}
		}

		// these routes match /.pomerium/... and similar paths
		vh.Routes = append(vh.Routes, buildPomeriumHTTPRoutes(options, domain)...)

		// if we're the proxy, add all the policy routes
		if config.IsProxy(options.Services) {
			vh.Routes = append(vh.Routes, buildPolicyRoutes(options, domain)...)
		}

		if len(vh.Routes) > 0 {
			virtualHosts = append(virtualHosts, vh)
		}
	}
	virtualHosts = append(virtualHosts, &envoy_config_route_v3.VirtualHost{
		Name:    "catch-all",
		Domains: []string{"*"},
		Routes:  buildPomeriumHTTPRoutes(options, "*"),
	})

	var grpcClientTimeout *durationpb.Duration
	if options.GRPCClientTimeout != 0 {
		grpcClientTimeout = ptypes.DurationProto(options.GRPCClientTimeout)
	} else {
		grpcClientTimeout = ptypes.DurationProto(30 * time.Second)
	}

	extAuthZ, _ := ptypes.MarshalAny(&envoy_extensions_filters_http_ext_authz_v3.ExtAuthz{
		StatusOnError: &envoy_type_v3.HttpStatus{
			Code: envoy_type_v3.StatusCode_InternalServerError,
		},
		Services: &envoy_extensions_filters_http_ext_authz_v3.ExtAuthz_GrpcService{
			GrpcService: &envoy_config_core_v3.GrpcService{
				Timeout: grpcClientTimeout,
				TargetSpecifier: &envoy_config_core_v3.GrpcService_EnvoyGrpc_{
					EnvoyGrpc: &envoy_config_core_v3.GrpcService_EnvoyGrpc{
						ClusterName: "pomerium-authz",
					},
				},
			},
		},
		IncludePeerCertificate: true,
	})

	extAuthzSetCookieLua, _ := ptypes.MarshalAny(&envoy_extensions_filters_http_lua_v3.Lua{
		InlineCode: luascripts.ExtAuthzSetCookie,
	})
	cleanUpstreamLua, _ := ptypes.MarshalAny(&envoy_extensions_filters_http_lua_v3.Lua{
		InlineCode: luascripts.CleanUpstream,
	})

	var maxStreamDuration *durationpb.Duration
	if options.WriteTimeout > 0 {
		maxStreamDuration = ptypes.DurationProto(options.WriteTimeout)
	}

	tc, _ := ptypes.MarshalAny(&envoy_http_connection_manager.HttpConnectionManager{
		CodecType:  envoy_http_connection_manager.HttpConnectionManager_AUTO,
		StatPrefix: "ingress",
		RouteSpecifier: &envoy_http_connection_manager.HttpConnectionManager_RouteConfig{
			RouteConfig: buildRouteConfiguration("main", virtualHosts),
		},
		HttpFilters: []*envoy_http_connection_manager.HttpFilter{
			{
				Name: "envoy.filters.http.ext_authz",
				ConfigType: &envoy_http_connection_manager.HttpFilter_TypedConfig{
					TypedConfig: extAuthZ,
				},
			},
			{
				Name: "envoy.filters.http.lua",
				ConfigType: &envoy_http_connection_manager.HttpFilter_TypedConfig{
					TypedConfig: extAuthzSetCookieLua,
				},
			},
			{
				Name: "envoy.filters.http.lua",
				ConfigType: &envoy_http_connection_manager.HttpFilter_TypedConfig{
					TypedConfig: cleanUpstreamLua,
				},
			},
			{
				Name: "envoy.filters.http.router",
			},
		},
		AccessLog: buildAccessLogs(options),
		CommonHttpProtocolOptions: &envoy_config_core_v3.HttpProtocolOptions{
			IdleTimeout:       ptypes.DurationProto(options.IdleTimeout),
			MaxStreamDuration: maxStreamDuration,
		},
		RequestTimeout: ptypes.DurationProto(options.ReadTimeout),
		Tracing: &envoy_http_connection_manager.HttpConnectionManager_Tracing{
			RandomSampling: &envoy_type_v3.Percent{Value: options.TracingSampleRate * 100},
		},
	})

	return &envoy_config_listener_v3.Filter{
		Name: "envoy.filters.network.http_connection_manager",
		ConfigType: &envoy_config_listener_v3.Filter_TypedConfig{
			TypedConfig: tc,
		},
	}
}

func buildGRPCListener(options *config.Options) *envoy_config_listener_v3.Listener {
	filter := buildGRPCHTTPConnectionManagerFilter()

	if options.GRPCInsecure {
		return &envoy_config_listener_v3.Listener{
			Name:    "grpc-ingress",
			Address: buildAddress(options.GRPCAddr, 80),
			FilterChains: []*envoy_config_listener_v3.FilterChain{{
				Filters: []*envoy_config_listener_v3.Filter{
					filter,
				},
			}},
		}
	}

	tlsInspectorCfg, _ := ptypes.MarshalAny(new(emptypb.Empty))
	li := &envoy_config_listener_v3.Listener{
		Name:    "grpc-ingress",
		Address: buildAddress(options.GRPCAddr, 443),
		ListenerFilters: []*envoy_config_listener_v3.ListenerFilter{{
			Name: "envoy.filters.listener.tls_inspector",
			ConfigType: &envoy_config_listener_v3.ListenerFilter_TypedConfig{
				TypedConfig: tlsInspectorCfg,
			},
		}},
		FilterChains: buildFilterChains(options, options.Addr,
			func(tlsDomain string, httpDomains []string) *envoy_config_listener_v3.FilterChain {
				filterChain := &envoy_config_listener_v3.FilterChain{
					Filters: []*envoy_config_listener_v3.Filter{filter},
				}
				if tlsDomain != "*" {
					filterChain.FilterChainMatch = &envoy_config_listener_v3.FilterChainMatch{
						ServerNames: []string{tlsDomain},
					}
				}
				tlsContext := buildDownstreamTLSContext(options, tlsDomain)
				if tlsContext != nil {
					tlsConfig, _ := ptypes.MarshalAny(tlsContext)
					filterChain.TransportSocket = &envoy_config_core_v3.TransportSocket{
						Name: "tls",
						ConfigType: &envoy_config_core_v3.TransportSocket_TypedConfig{
							TypedConfig: tlsConfig,
						},
					}
				}
				return filterChain
			}),
	}
	return li
}

func buildGRPCHTTPConnectionManagerFilter() *envoy_config_listener_v3.Filter {
	tc, _ := ptypes.MarshalAny(&envoy_http_connection_manager.HttpConnectionManager{
		CodecType:  envoy_http_connection_manager.HttpConnectionManager_AUTO,
		StatPrefix: "grpc_ingress",
		RouteSpecifier: &envoy_http_connection_manager.HttpConnectionManager_RouteConfig{
			RouteConfig: buildRouteConfiguration("grpc", []*envoy_config_route_v3.VirtualHost{{
				Name:    "grpc",
				Domains: []string{"*"},
				Routes: []*envoy_config_route_v3.Route{{
					Name: "grpc",
					Match: &envoy_config_route_v3.RouteMatch{
						PathSpecifier: &envoy_config_route_v3.RouteMatch_Prefix{Prefix: "/"},
						Grpc:          &envoy_config_route_v3.RouteMatch_GrpcRouteMatchOptions{},
					},
					Action: &envoy_config_route_v3.Route_Route{
						Route: &envoy_config_route_v3.RouteAction{
							ClusterSpecifier: &envoy_config_route_v3.RouteAction_Cluster{
								Cluster: "pomerium-control-plane-grpc",
							},
						},
					},
				}},
			}}),
		},
		HttpFilters: []*envoy_http_connection_manager.HttpFilter{{
			Name: "envoy.filters.http.router",
		}},
	})
	return &envoy_config_listener_v3.Filter{
		Name: "envoy.filters.network.http_connection_manager",
		ConfigType: &envoy_config_listener_v3.Filter_TypedConfig{
			TypedConfig: tc,
		},
	}
}

func buildRouteConfiguration(name string, virtualHosts []*envoy_config_route_v3.VirtualHost) *envoy_config_route_v3.RouteConfiguration {
	return &envoy_config_route_v3.RouteConfiguration{
		Name:         name,
		VirtualHosts: virtualHosts,
		// disable cluster validation since the order of LDS/CDS updates isn't guaranteed
		ValidateClusters: &wrappers.BoolValue{Value: false},
	}
}

func buildDownstreamTLSContext(options *config.Options, domain string) *envoy_extensions_transport_sockets_tls_v3.DownstreamTlsContext {
	cert, err := cryptutil.GetCertificateForDomain(options.Certificates, domain)
	if err != nil {
		log.Warn().Str("domain", domain).Err(err).Msg("failed to get certificate for domain")
		return nil
	}

	var trustedCA *envoy_config_core_v3.DataSource
	if options.ClientCA != "" {
		bs, err := base64.StdEncoding.DecodeString(options.ClientCA)
		if err != nil {
			log.Warn().Msg("client_ca does not appear to be a base64 encoded string")
		}
		trustedCA = inlineBytesAsFilename("client-ca", bs)
	} else if options.ClientCAFile != "" {
		trustedCA = inlineFilename(options.ClientCAFile)
	}

	var validationContext *envoy_extensions_transport_sockets_tls_v3.CommonTlsContext_ValidationContext
	if trustedCA != nil {
		validationContext = &envoy_extensions_transport_sockets_tls_v3.CommonTlsContext_ValidationContext{
			ValidationContext: &envoy_extensions_transport_sockets_tls_v3.CertificateValidationContext{
				TrustedCa:              trustedCA,
				TrustChainVerification: envoy_extensions_transport_sockets_tls_v3.CertificateValidationContext_ACCEPT_UNTRUSTED,
			},
		}
	}

	envoyCert := envoyTLSCertificateFromGoTLSCertificate(cert)
	return &envoy_extensions_transport_sockets_tls_v3.DownstreamTlsContext{
		CommonTlsContext: &envoy_extensions_transport_sockets_tls_v3.CommonTlsContext{
			TlsParams: &envoy_extensions_transport_sockets_tls_v3.TlsParameters{
				TlsMinimumProtocolVersion: envoy_extensions_transport_sockets_tls_v3.TlsParameters_TLSv1_2,
			},
			TlsCertificates:       []*envoy_extensions_transport_sockets_tls_v3.TlsCertificate{envoyCert},
			AlpnProtocols:         []string{"h2", "http/1.1"},
			ValidationContextType: validationContext,
		},
	}
}

func getAllRouteableDomains(options *config.Options, addr string) []string {
	lookup := map[string]struct{}{}
	if config.IsAuthenticate(options.Services) && addr == options.Addr {
		lookup[options.GetAuthenticateURL().Host] = struct{}{}
	}
	if config.IsAuthorize(options.Services) && addr == options.GRPCAddr {
		lookup[options.GetAuthorizeURL().Host] = struct{}{}
	}
	if config.IsCache(options.Services) && addr == options.GRPCAddr {
		lookup[options.GetCacheURL().Host] = struct{}{}
	}
	if config.IsProxy(options.Services) && addr == options.Addr {
		for _, policy := range options.Policies {
			lookup[policy.Source.Host] = struct{}{}
		}
		if options.ForwardAuthURL != nil {
			lookup[options.ForwardAuthURL.Host] = struct{}{}
		}
	}

	domains := make([]string, 0, len(lookup))
	for domain := range lookup {
		domains = append(domains, domain)
	}
	sort.Strings(domains)

	return domains
}
