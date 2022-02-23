package envoyconfig

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"sort"
	"time"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_listener_v3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_config_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoy_extensions_filters_http_ext_authz_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_authz/v3"
	envoy_extensions_filters_http_lua_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/lua/v3"
	envoy_extensions_filters_listener_proxy_protocol_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/listener/proxy_protocol/v3"
	envoy_http_connection_manager "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	envoy_extensions_transport_sockets_tls_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	envoy_type_v3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/golang/protobuf/ptypes/any"
	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/scylladb/go-set"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/hashutil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
)

const listenerBufferLimit uint32 = 32 * 1024

var (
	disableExtAuthz *any.Any
	tlsParams       = &envoy_extensions_transport_sockets_tls_v3.TlsParameters{
		CipherSuites: []string{
			"ECDHE-ECDSA-AES256-GCM-SHA384",
			"ECDHE-RSA-AES256-GCM-SHA384",
			"ECDHE-ECDSA-AES128-GCM-SHA256",
			"ECDHE-RSA-AES128-GCM-SHA256",
			"ECDHE-ECDSA-CHACHA20-POLY1305",
			"ECDHE-RSA-CHACHA20-POLY1305",
		},
		TlsMinimumProtocolVersion: envoy_extensions_transport_sockets_tls_v3.TlsParameters_TLSv1_2,
	}
)

func init() {
	disableExtAuthz = marshalAny(&envoy_extensions_filters_http_ext_authz_v3.ExtAuthzPerRoute{
		Override: &envoy_extensions_filters_http_ext_authz_v3.ExtAuthzPerRoute_Disabled{
			Disabled: true,
		},
	})
}

// BuildListeners builds envoy listeners from the given config.
func (b *Builder) BuildListeners(ctx context.Context, cfg *config.Config) ([]*envoy_config_listener_v3.Listener, error) {
	var listeners []*envoy_config_listener_v3.Listener

	if config.IsAuthenticate(cfg.Options.Services) || config.IsProxy(cfg.Options.Services) {
		li, err := b.buildMainListener(ctx, cfg)
		if err != nil {
			return nil, err
		}
		listeners = append(listeners, li)
	}

	if config.IsAuthorize(cfg.Options.Services) || config.IsDataBroker(cfg.Options.Services) {
		li, err := b.buildGRPCListener(ctx, cfg)
		if err != nil {
			return nil, err
		}
		listeners = append(listeners, li)
	}

	if cfg.Options.MetricsAddr != "" {
		li, err := b.buildMetricsListener(cfg)
		if err != nil {
			return nil, err
		}
		listeners = append(listeners, li)
	}

	li, err := b.buildOutboundListener(cfg)
	if err != nil {
		return nil, err
	}
	listeners = append(listeners, li)

	return listeners, nil
}

func (b *Builder) buildMainListener(ctx context.Context, cfg *config.Config) (*envoy_config_listener_v3.Listener, error) {
	listenerFilters := []*envoy_config_listener_v3.ListenerFilter{}
	if cfg.Options.UseProxyProtocol {
		proxyCfg := marshalAny(&envoy_extensions_filters_listener_proxy_protocol_v3.ProxyProtocol{})
		listenerFilters = append(listenerFilters, &envoy_config_listener_v3.ListenerFilter{
			Name: "envoy.filters.listener.proxy_protocol",
			ConfigType: &envoy_config_listener_v3.ListenerFilter_TypedConfig{
				TypedConfig: proxyCfg,
			},
		})
	}

	if cfg.Options.InsecureServer {
		allDomains, err := getAllRouteableDomains(cfg.Options, cfg.Options.Addr)
		if err != nil {
			return nil, err
		}

		filter, err := b.buildMainHTTPConnectionManagerFilter(cfg.Options, allDomains, "")
		if err != nil {
			return nil, err
		}

		li := newEnvoyListener("http-ingress")
		li.Address = buildAddress(cfg.Options.Addr, 80)
		li.ListenerFilters = listenerFilters
		li.FilterChains = []*envoy_config_listener_v3.FilterChain{{
			Filters: []*envoy_config_listener_v3.Filter{
				filter,
			},
		}}
		return li, nil
	}

	tlsInspectorCfg := marshalAny(new(emptypb.Empty))
	listenerFilters = append(listenerFilters, &envoy_config_listener_v3.ListenerFilter{
		Name: "envoy.filters.listener.tls_inspector",
		ConfigType: &envoy_config_listener_v3.ListenerFilter_TypedConfig{
			TypedConfig: tlsInspectorCfg,
		},
	})

	chains, err := b.buildFilterChains(cfg.Options, cfg.Options.Addr,
		func(tlsDomain string, httpDomains []string) (*envoy_config_listener_v3.FilterChain, error) {
			filter, err := b.buildMainHTTPConnectionManagerFilter(cfg.Options, httpDomains, tlsDomain)
			if err != nil {
				return nil, err
			}
			filterChain := &envoy_config_listener_v3.FilterChain{
				Filters: []*envoy_config_listener_v3.Filter{filter},
			}
			if tlsDomain != "*" {
				filterChain.FilterChainMatch = &envoy_config_listener_v3.FilterChainMatch{
					ServerNames: []string{tlsDomain},
				}
			}
			tlsContext := b.buildDownstreamTLSContext(ctx, cfg, tlsDomain)
			if tlsContext != nil {
				tlsConfig := marshalAny(tlsContext)
				filterChain.TransportSocket = &envoy_config_core_v3.TransportSocket{
					Name: "tls",
					ConfigType: &envoy_config_core_v3.TransportSocket_TypedConfig{
						TypedConfig: tlsConfig,
					},
				}
			}
			return filterChain, nil
		})
	if err != nil {
		return nil, err
	}

	li := newEnvoyListener("https-ingress")
	li.Address = buildAddress(cfg.Options.Addr, 443)
	li.ListenerFilters = listenerFilters
	li.FilterChains = chains
	return li, nil
}

func (b *Builder) buildMetricsListener(cfg *config.Config) (*envoy_config_listener_v3.Listener, error) {
	filter, err := b.buildMetricsHTTPConnectionManagerFilter()
	if err != nil {
		return nil, err
	}

	filterChain := &envoy_config_listener_v3.FilterChain{
		Filters: []*envoy_config_listener_v3.Filter{
			filter,
		},
	}

	cert, err := cfg.Options.GetMetricsCertificate()
	if err != nil {
		return nil, err
	}
	if cert != nil {
		dtc := &envoy_extensions_transport_sockets_tls_v3.DownstreamTlsContext{
			CommonTlsContext: &envoy_extensions_transport_sockets_tls_v3.CommonTlsContext{
				TlsParams: tlsParams,
				TlsCertificates: []*envoy_extensions_transport_sockets_tls_v3.TlsCertificate{
					b.envoyTLSCertificateFromGoTLSCertificate(context.TODO(), cert),
				},
				AlpnProtocols: []string{"h2", "http/1.1"},
			},
		}

		if cfg.Options.MetricsClientCA != "" {
			bs, err := base64.StdEncoding.DecodeString(cfg.Options.MetricsClientCA)
			if err != nil {
				return nil, fmt.Errorf("xds: invalid metrics_client_ca: %w", err)
			}

			dtc.RequireClientCertificate = wrapperspb.Bool(true)
			dtc.CommonTlsContext.ValidationContextType = &envoy_extensions_transport_sockets_tls_v3.CommonTlsContext_ValidationContext{
				ValidationContext: &envoy_extensions_transport_sockets_tls_v3.CertificateValidationContext{
					TrustChainVerification: envoy_extensions_transport_sockets_tls_v3.CertificateValidationContext_VERIFY_TRUST_CHAIN,
					TrustedCa:              b.filemgr.BytesDataSource("metrics_client_ca.pem", bs),
				},
			}
		} else if cfg.Options.MetricsClientCAFile != "" {
			dtc.RequireClientCertificate = wrapperspb.Bool(true)
			dtc.CommonTlsContext.ValidationContextType = &envoy_extensions_transport_sockets_tls_v3.CommonTlsContext_ValidationContext{
				ValidationContext: &envoy_extensions_transport_sockets_tls_v3.CertificateValidationContext{
					TrustChainVerification: envoy_extensions_transport_sockets_tls_v3.CertificateValidationContext_VERIFY_TRUST_CHAIN,
					TrustedCa:              b.filemgr.FileDataSource(cfg.Options.MetricsClientCAFile),
				},
			}
		}

		tc := marshalAny(dtc)
		filterChain.TransportSocket = &envoy_config_core_v3.TransportSocket{
			Name: "tls",
			ConfigType: &envoy_config_core_v3.TransportSocket_TypedConfig{
				TypedConfig: tc,
			},
		}
	}

	// we ignore the host part of the address, only binding to
	host, port, err := net.SplitHostPort(cfg.Options.MetricsAddr)
	if err != nil {
		return nil, fmt.Errorf("metrics_addr %s: %w", cfg.Options.MetricsAddr, err)
	}
	if port == "" {
		return nil, fmt.Errorf("metrics_addr %s: port is required", cfg.Options.MetricsAddr)
	}
	// unless an explicit IP address was provided, and bind to all interfaces if hostname was provided
	if net.ParseIP(host) == nil {
		host = ""
	}

	addr := buildAddress(fmt.Sprintf("%s:%s", host, port), 9902)
	li := newEnvoyListener(fmt.Sprintf("metrics-ingress-%d", hashutil.MustHash(addr)))
	li.Address = addr
	li.FilterChains = []*envoy_config_listener_v3.FilterChain{filterChain}
	return li, nil
}

func (b *Builder) buildFilterChains(
	options *config.Options, addr string,
	callback func(tlsDomain string, httpDomains []string) (*envoy_config_listener_v3.FilterChain, error),
) ([]*envoy_config_listener_v3.FilterChain, error) {
	allDomains, err := getAllRouteableDomains(options, addr)
	if err != nil {
		return nil, err
	}

	tlsDomains, err := getAllTLSDomains(options, addr)
	if err != nil {
		return nil, err
	}

	var chains []*envoy_config_listener_v3.FilterChain
	for _, domain := range tlsDomains {
		routeableDomains, err := getRouteableDomainsForTLSDomain(options, addr, domain)
		if err != nil {
			return nil, err
		}

		// first we match on SNI
		chain, err := callback(domain, routeableDomains)
		if err != nil {
			return nil, err
		}
		chains = append(chains, chain)
	}

	// if there are no SNI matches we match on HTTP host
	chain, err := callback("*", allDomains)
	if err != nil {
		return nil, err
	}
	chains = append(chains, chain)
	return chains, nil
}

func (b *Builder) buildMainHTTPConnectionManagerFilter(
	options *config.Options,
	domains []string,
	tlsDomain string,
) (*envoy_config_listener_v3.Filter, error) {
	authorizeURLs, err := options.GetInternalAuthorizeURLs()
	if err != nil {
		return nil, err
	}

	dataBrokerURLs, err := options.GetInternalDataBrokerURLs()
	if err != nil {
		return nil, err
	}

	var virtualHosts []*envoy_config_route_v3.VirtualHost
	for _, domain := range domains {
		vh, err := b.buildVirtualHost(options, domain, domain)
		if err != nil {
			return nil, err
		}

		if options.Addr == options.GetGRPCAddr() {
			// if this is a gRPC service domain and we're supposed to handle that, add those routes
			if (config.IsAuthorize(options.Services) && hostsMatchDomain(authorizeURLs, domain)) ||
				(config.IsDataBroker(options.Services) && hostsMatchDomain(dataBrokerURLs, domain)) {
				rs, err := b.buildGRPCRoutes()
				if err != nil {
					return nil, err
				}
				vh.Routes = append(vh.Routes, rs...)
			}
		}

		// if we're the proxy, add all the policy routes
		if config.IsProxy(options.Services) {
			rs, err := b.buildPolicyRoutes(options, domain)
			if err != nil {
				return nil, err
			}
			vh.Routes = append(vh.Routes, rs...)
		}

		if len(vh.Routes) > 0 {
			virtualHosts = append(virtualHosts, vh)
		}
	}

	vh, err := b.buildVirtualHost(options, "catch-all", "*")
	if err != nil {
		return nil, err
	}
	virtualHosts = append(virtualHosts, vh)

	var grpcClientTimeout *durationpb.Duration
	if options.GRPCClientTimeout != 0 {
		grpcClientTimeout = durationpb.New(options.GRPCClientTimeout)
	} else {
		grpcClientTimeout = durationpb.New(30 * time.Second)
	}

	extAuthZ := marshalAny(&envoy_extensions_filters_http_ext_authz_v3.ExtAuthz{
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
		IncludePeerCertificate: true,
		TransportApiVersion:    envoy_config_core_v3.ApiVersion_V3,
	})

	extAuthzSetCookieLua := marshalAny(&envoy_extensions_filters_http_lua_v3.Lua{
		InlineCode: luascripts.ExtAuthzSetCookie,
	})
	cleanUpstreamLua := marshalAny(&envoy_extensions_filters_http_lua_v3.Lua{
		InlineCode: luascripts.CleanUpstream,
	})
	removeImpersonateHeadersLua := marshalAny(&envoy_extensions_filters_http_lua_v3.Lua{
		InlineCode: luascripts.RemoveImpersonateHeaders,
	})
	rewriteHeadersLua := marshalAny(&envoy_extensions_filters_http_lua_v3.Lua{
		InlineCode: luascripts.RewriteHeaders,
	})

	filters := []*envoy_http_connection_manager.HttpFilter{
		{
			Name: "envoy.filters.http.lua",
			ConfigType: &envoy_http_connection_manager.HttpFilter_TypedConfig{
				TypedConfig: removeImpersonateHeadersLua,
			},
		},
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
			Name: "envoy.filters.http.lua",
			ConfigType: &envoy_http_connection_manager.HttpFilter_TypedConfig{
				TypedConfig: rewriteHeadersLua,
			},
		},
	}
	if tlsDomain != "" && tlsDomain != "*" {
		fixMisdirectedLua := marshalAny(&envoy_extensions_filters_http_lua_v3.Lua{
			InlineCode: fmt.Sprintf(luascripts.FixMisdirected, tlsDomain),
		})
		filters = append(filters, &envoy_http_connection_manager.HttpFilter{
			Name: "envoy.filters.http.lua",
			ConfigType: &envoy_http_connection_manager.HttpFilter_TypedConfig{
				TypedConfig: fixMisdirectedLua,
			},
		})
	}
	filters = append(filters, &envoy_http_connection_manager.HttpFilter{
		Name: "envoy.filters.http.router",
	})

	var maxStreamDuration *durationpb.Duration
	if options.WriteTimeout > 0 {
		maxStreamDuration = durationpb.New(options.WriteTimeout)
	}

	rc, err := b.buildRouteConfiguration("main", virtualHosts)
	if err != nil {
		return nil, err
	}
	tracingProvider, err := buildTracingHTTP(options)
	if err != nil {
		return nil, err
	}
	tc := marshalAny(&envoy_http_connection_manager.HttpConnectionManager{
		CodecType:  options.GetCodecType().ToEnvoy(),
		StatPrefix: "ingress",
		RouteSpecifier: &envoy_http_connection_manager.HttpConnectionManager_RouteConfig{
			RouteConfig: rc,
		},
		HttpFilters: filters,
		AccessLog:   buildAccessLogs(options),
		CommonHttpProtocolOptions: &envoy_config_core_v3.HttpProtocolOptions{
			IdleTimeout:       durationpb.New(options.IdleTimeout),
			MaxStreamDuration: maxStreamDuration,
		},
		RequestTimeout: durationpb.New(options.ReadTimeout),
		Tracing: &envoy_http_connection_manager.HttpConnectionManager_Tracing{
			RandomSampling: &envoy_type_v3.Percent{Value: options.TracingSampleRate * 100},
			Provider:       tracingProvider,
		},
		// See https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_conn_man/headers#x-forwarded-for
		UseRemoteAddress:  &wrappers.BoolValue{Value: true},
		SkipXffAppend:     options.SkipXffAppend,
		XffNumTrustedHops: options.XffNumTrustedHops,
		LocalReplyConfig:  b.buildLocalReplyConfig(options),
	})

	return &envoy_config_listener_v3.Filter{
		Name: "envoy.filters.network.http_connection_manager",
		ConfigType: &envoy_config_listener_v3.Filter_TypedConfig{
			TypedConfig: tc,
		},
	}, nil
}

func (b *Builder) buildMetricsHTTPConnectionManagerFilter() (*envoy_config_listener_v3.Filter, error) {
	rc, err := b.buildRouteConfiguration("metrics", []*envoy_config_route_v3.VirtualHost{{
		Name:    "metrics",
		Domains: []string{"*"},
		Routes: []*envoy_config_route_v3.Route{{
			Name: "metrics",
			Match: &envoy_config_route_v3.RouteMatch{
				PathSpecifier: &envoy_config_route_v3.RouteMatch_Prefix{Prefix: "/"},
			},
			Action: &envoy_config_route_v3.Route_Route{
				Route: &envoy_config_route_v3.RouteAction{
					ClusterSpecifier: &envoy_config_route_v3.RouteAction_Cluster{
						Cluster: "pomerium-control-plane-http",
					},
				},
			},
		}},
	}})
	if err != nil {
		return nil, err
	}

	tc := marshalAny(&envoy_http_connection_manager.HttpConnectionManager{
		CodecType:  envoy_http_connection_manager.HttpConnectionManager_AUTO,
		StatPrefix: "metrics",
		RouteSpecifier: &envoy_http_connection_manager.HttpConnectionManager_RouteConfig{
			RouteConfig: rc,
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
	}, nil
}

func (b *Builder) buildGRPCListener(ctx context.Context, cfg *config.Config) (*envoy_config_listener_v3.Listener, error) {
	filter, err := b.buildGRPCHTTPConnectionManagerFilter()
	if err != nil {
		return nil, err
	}

	if cfg.Options.GetGRPCInsecure() {
		li := newEnvoyListener("grpc-ingress")
		li.Address = buildAddress(cfg.Options.GetGRPCAddr(), 80)
		li.FilterChains = []*envoy_config_listener_v3.FilterChain{{
			Filters: []*envoy_config_listener_v3.Filter{
				filter,
			},
		}}
		return li, nil
	}

	chains, err := b.buildFilterChains(cfg.Options, cfg.Options.GRPCAddr,
		func(tlsDomain string, httpDomains []string) (*envoy_config_listener_v3.FilterChain, error) {
			filterChain := &envoy_config_listener_v3.FilterChain{
				Filters: []*envoy_config_listener_v3.Filter{filter},
			}
			if tlsDomain != "*" {
				filterChain.FilterChainMatch = &envoy_config_listener_v3.FilterChainMatch{
					ServerNames: []string{tlsDomain},
				}
			}
			tlsContext := b.buildDownstreamTLSContext(ctx, cfg, tlsDomain)
			if tlsContext != nil {
				tlsConfig := marshalAny(tlsContext)
				filterChain.TransportSocket = &envoy_config_core_v3.TransportSocket{
					Name: "tls",
					ConfigType: &envoy_config_core_v3.TransportSocket_TypedConfig{
						TypedConfig: tlsConfig,
					},
				}
			}
			return filterChain, nil
		})
	if err != nil {
		return nil, err
	}

	tlsInspectorCfg := marshalAny(new(emptypb.Empty))
	li := newEnvoyListener("grpc-ingress")
	li.Address = buildAddress(cfg.Options.GetGRPCAddr(), 443)
	li.ListenerFilters = []*envoy_config_listener_v3.ListenerFilter{{
		Name: "envoy.filters.listener.tls_inspector",
		ConfigType: &envoy_config_listener_v3.ListenerFilter_TypedConfig{
			TypedConfig: tlsInspectorCfg,
		},
	}}
	li.FilterChains = chains
	return li, nil
}

func (b *Builder) buildGRPCHTTPConnectionManagerFilter() (*envoy_config_listener_v3.Filter, error) {
	rc, err := b.buildRouteConfiguration("grpc", []*envoy_config_route_v3.VirtualHost{{
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
					// disable the timeout to support grpc streaming
					Timeout: &durationpb.Duration{
						Seconds: 0,
					},
					IdleTimeout: &durationpb.Duration{
						Seconds: 0,
					},
				},
			},
		}},
	}})
	if err != nil {
		return nil, err
	}

	tc := marshalAny(&envoy_http_connection_manager.HttpConnectionManager{
		CodecType:  envoy_http_connection_manager.HttpConnectionManager_AUTO,
		StatPrefix: "grpc_ingress",
		// limit request first byte to last byte time
		RequestTimeout: &durationpb.Duration{
			Seconds: 15,
		},
		RouteSpecifier: &envoy_http_connection_manager.HttpConnectionManager_RouteConfig{
			RouteConfig: rc,
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
	}, nil
}

func (b *Builder) buildRouteConfiguration(name string, virtualHosts []*envoy_config_route_v3.VirtualHost) (*envoy_config_route_v3.RouteConfiguration, error) {
	return &envoy_config_route_v3.RouteConfiguration{
		Name:         name,
		VirtualHosts: virtualHosts,
		// disable cluster validation since the order of LDS/CDS updates isn't guaranteed
		ValidateClusters: &wrappers.BoolValue{Value: false},
	}, nil
}

func (b *Builder) buildDownstreamTLSContext(ctx context.Context,
	cfg *config.Config,
	domain string,
) *envoy_extensions_transport_sockets_tls_v3.DownstreamTlsContext {
	certs, err := cfg.AllCertificates()
	if err != nil {
		log.Warn(ctx).Str("domain", domain).Err(err).Msg("failed to get all certificates from config")
		return nil
	}

	cert, err := cryptutil.GetCertificateForDomain(certs, domain)
	if err != nil {
		log.Warn(ctx).Str("domain", domain).Err(err).Msg("failed to get certificate for domain")
		return nil
	}

	err = validateCertificate(cert)
	if err != nil {
		log.Warn(ctx).Str("domain", domain).Err(err).Msg("invalid certificate for domain")
		return nil
	}

	var alpnProtocols []string
	switch cfg.Options.GetCodecType() {
	case config.CodecTypeHTTP1:
		alpnProtocols = []string{"http/1.1"}
	case config.CodecTypeHTTP2:
		alpnProtocols = []string{"h2"}
	default:
		alpnProtocols = []string{"h2", "http/1.1"}
	}

	envoyCert := b.envoyTLSCertificateFromGoTLSCertificate(ctx, cert)
	return &envoy_extensions_transport_sockets_tls_v3.DownstreamTlsContext{
		CommonTlsContext: &envoy_extensions_transport_sockets_tls_v3.CommonTlsContext{
			TlsParams:             tlsParams,
			TlsCertificates:       []*envoy_extensions_transport_sockets_tls_v3.TlsCertificate{envoyCert},
			AlpnProtocols:         alpnProtocols,
			ValidationContextType: b.buildDownstreamValidationContext(ctx, cfg, domain),
		},
	}
}

func (b *Builder) buildDownstreamValidationContext(ctx context.Context,
	cfg *config.Config,
	domain string,
) *envoy_extensions_transport_sockets_tls_v3.CommonTlsContext_ValidationContext {
	needsClientCert := false

	if ca, _ := cfg.Options.GetClientCA(); len(ca) > 0 {
		needsClientCert = true
	}
	if !needsClientCert {
		for _, p := range getPoliciesForDomain(cfg.Options, domain) {
			if p.TLSDownstreamClientCA != "" {
				needsClientCert = true
				break
			}
		}
	}

	if !needsClientCert {
		return nil
	}

	// trusted_ca is left blank because we verify the client certificate in the authorize service
	vc := &envoy_extensions_transport_sockets_tls_v3.CommonTlsContext_ValidationContext{
		ValidationContext: &envoy_extensions_transport_sockets_tls_v3.CertificateValidationContext{
			TrustChainVerification: envoy_extensions_transport_sockets_tls_v3.CertificateValidationContext_ACCEPT_UNTRUSTED,
		},
	}

	if cfg.Options.ClientCRL != "" {
		bs, err := base64.StdEncoding.DecodeString(cfg.Options.ClientCRL)
		if err != nil {
			log.Error(ctx).Err(err).Msg("invalid client CRL")
		} else {
			vc.ValidationContext.Crl = b.filemgr.BytesDataSource("client-crl.pem", bs)
		}
	} else if cfg.Options.ClientCRLFile != "" {
		vc.ValidationContext.Crl = b.filemgr.FileDataSource(cfg.Options.ClientCRLFile)
	}

	return vc
}

func getRouteableDomainsForTLSDomain(options *config.Options, addr string, tlsDomain string) ([]string, error) {
	allDomains, err := getAllRouteableDomains(options, addr)
	if err != nil {
		return nil, err
	}

	var filtered []string
	for _, domain := range allDomains {
		if urlutil.StripPort(domain) == tlsDomain {
			filtered = append(filtered, domain)
		}
	}
	return filtered, nil
}

func getAllRouteableDomains(options *config.Options, addr string) ([]string, error) {
	allDomains := set.NewStringSet()

	if addr == options.Addr {
		domains, err := options.GetAllRouteableHTTPDomains()
		if err != nil {
			return nil, err
		}
		allDomains.Add(domains...)
	}

	if addr == options.GetGRPCAddr() {
		domains, err := options.GetAllRouteableGRPCDomains()
		if err != nil {
			return nil, err
		}
		allDomains.Add(domains...)
	}

	domains := allDomains.List()
	sort.Strings(domains)

	return domains, nil
}

func getAllTLSDomains(options *config.Options, addr string) ([]string, error) {
	allDomains, err := getAllRouteableDomains(options, addr)
	if err != nil {
		return nil, err
	}

	lookup := map[string]struct{}{}
	for _, hp := range allDomains {
		if d, _, err := net.SplitHostPort(hp); err == nil {
			lookup[d] = struct{}{}
		} else {
			lookup[hp] = struct{}{}
		}
	}

	domains := make([]string, 0, len(lookup))
	for domain := range lookup {
		domains = append(domains, domain)
	}
	sort.Strings(domains)

	return domains, nil
}

func hostsMatchDomain(urls []*url.URL, host string) bool {
	for _, u := range urls {
		if hostMatchesDomain(u, host) {
			return true
		}
	}
	return false
}

func hostMatchesDomain(u *url.URL, host string) bool {
	if u == nil {
		return false
	}

	var defaultPort string
	if u.Scheme == "http" {
		defaultPort = "80"
	} else {
		defaultPort = "443"
	}

	h1, p1, err := net.SplitHostPort(u.Host)
	if err != nil {
		h1 = u.Host
		p1 = defaultPort
	}

	h2, p2, err := net.SplitHostPort(host)
	if err != nil {
		h2 = host
		p2 = defaultPort
	}

	return h1 == h2 && p1 == p2
}

func getPoliciesForDomain(options *config.Options, domain string) []config.Policy {
	var policies []config.Policy
	for _, p := range options.GetAllPolicies() {
		if p.Source != nil && p.Source.URL.Hostname() == domain {
			policies = append(policies, p)
		}
	}
	return policies
}

// newEnvoyListener creates envoy listener with certain default values
func newEnvoyListener(name string) *envoy_config_listener_v3.Listener {
	return &envoy_config_listener_v3.Listener{
		Name:                          name,
		PerConnectionBufferLimitBytes: wrapperspb.UInt32(listenerBufferLimit),
	}
}
