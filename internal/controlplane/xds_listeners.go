package controlplane

import (
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
	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/any"
	"github.com/golang/protobuf/ptypes/wrappers"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
)

var disableExtAuthz *any.Any

func init() {
	disableExtAuthz = marshalAny(&envoy_extensions_filters_http_ext_authz_v3.ExtAuthzPerRoute{
		Override: &envoy_extensions_filters_http_ext_authz_v3.ExtAuthzPerRoute_Disabled{
			Disabled: true,
		},
	})
}

func (srv *Server) buildListeners(cfg *config.Config) ([]*envoy_config_listener_v3.Listener, error) {
	var listeners []*envoy_config_listener_v3.Listener

	if config.IsAuthenticate(cfg.Options.Services) || config.IsProxy(cfg.Options.Services) {
		li, err := srv.buildMainListener(cfg)
		if err != nil {
			return nil, err
		}
		listeners = append(listeners, li)
	}

	if config.IsAuthorize(cfg.Options.Services) || config.IsDataBroker(cfg.Options.Services) {
		li, err := srv.buildGRPCListener(cfg)
		if err != nil {
			return nil, err
		}
		listeners = append(listeners, li)
	}

	return listeners, nil
}

func (srv *Server) buildMainListener(cfg *config.Config) (*envoy_config_listener_v3.Listener, error) {
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

		filter, err := srv.buildMainHTTPConnectionManagerFilter(cfg.Options, allDomains, "")
		if err != nil {
			return nil, err
		}

		return &envoy_config_listener_v3.Listener{
			Name:            "http-ingress",
			Address:         buildAddress(cfg.Options.Addr, 80),
			ListenerFilters: listenerFilters,
			FilterChains: []*envoy_config_listener_v3.FilterChain{{
				Filters: []*envoy_config_listener_v3.Filter{
					filter,
				},
			}},
		}, nil
	}

	tlsInspectorCfg := marshalAny(new(emptypb.Empty))
	listenerFilters = append(listenerFilters, &envoy_config_listener_v3.ListenerFilter{
		Name: "envoy.filters.listener.tls_inspector",
		ConfigType: &envoy_config_listener_v3.ListenerFilter_TypedConfig{
			TypedConfig: tlsInspectorCfg,
		},
	})

	chains, err := srv.buildFilterChains(cfg.Options, cfg.Options.Addr,
		func(tlsDomain string, httpDomains []string) (*envoy_config_listener_v3.FilterChain, error) {
			filter, err := srv.buildMainHTTPConnectionManagerFilter(cfg.Options, httpDomains, tlsDomain)
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
			tlsContext := srv.buildDownstreamTLSContext(cfg, tlsDomain)
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

	li := &envoy_config_listener_v3.Listener{
		Name:            "https-ingress",
		Address:         buildAddress(cfg.Options.Addr, 443),
		ListenerFilters: listenerFilters,
		FilterChains:    chains,
	}
	return li, nil
}

func (srv *Server) buildFilterChains(
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

func (srv *Server) buildMainHTTPConnectionManagerFilter(
	options *config.Options,
	domains []string,
	tlsDomain string,
) (*envoy_config_listener_v3.Filter, error) {
	authorizeURL, err := options.GetAuthorizeURL()
	if err != nil {
		return nil, err
	}

	dataBrokerURL, err := options.GetDataBrokerURL()
	if err != nil {
		return nil, err
	}

	var virtualHosts []*envoy_config_route_v3.VirtualHost
	for _, domain := range domains {
		vh := &envoy_config_route_v3.VirtualHost{
			Name:    domain,
			Domains: []string{domain},
		}

		if options.Addr == options.GRPCAddr {
			// if this is a gRPC service domain and we're supposed to handle that, add those routes
			if (config.IsAuthorize(options.Services) && hostMatchesDomain(authorizeURL, domain)) ||
				(config.IsDataBroker(options.Services) && hostMatchesDomain(dataBrokerURL, domain)) {
				rs, err := srv.buildGRPCRoutes()
				if err != nil {
					return nil, err
				}
				vh.Routes = append(vh.Routes, rs...)
			}
		}

		// these routes match /.pomerium/... and similar paths
		rs, err := srv.buildPomeriumHTTPRoutes(options, domain)
		if err != nil {
			return nil, err
		}
		vh.Routes = append(vh.Routes, rs...)

		// if we're the proxy, add all the policy routes
		if config.IsProxy(options.Services) {
			rs, err := srv.buildPolicyRoutes(options, domain)
			if err != nil {
				return nil, err
			}
			vh.Routes = append(vh.Routes, rs...)
		}

		if len(vh.Routes) > 0 {
			virtualHosts = append(virtualHosts, vh)
		}
	}

	rs, err := srv.buildPomeriumHTTPRoutes(options, "*")
	if err != nil {
		return nil, err
	}
	virtualHosts = append(virtualHosts, &envoy_config_route_v3.VirtualHost{
		Name:    "catch-all",
		Domains: []string{"*"},
		Routes:  rs,
	})

	var grpcClientTimeout *durationpb.Duration
	if options.GRPCClientTimeout != 0 {
		grpcClientTimeout = ptypes.DurationProto(options.GRPCClientTimeout)
	} else {
		grpcClientTimeout = ptypes.DurationProto(30 * time.Second)
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
						ClusterName: authorizeURL.Host,
					},
				},
			},
		},
		IncludePeerCertificate: true,
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
	}
	if tlsDomain != "" && tlsDomain != "*" {
		fixMisdirectedLua := marshalAny(&envoy_extensions_filters_http_lua_v3.Lua{
			InlineCode: fmt.Sprintf(luascripts.FixMisdirected),
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
		maxStreamDuration = ptypes.DurationProto(options.WriteTimeout)
	}

	rc, err := srv.buildRouteConfiguration("main", virtualHosts)
	if err != nil {
		return nil, err
	}
	tc := marshalAny(&envoy_http_connection_manager.HttpConnectionManager{
		CodecType:  envoy_http_connection_manager.HttpConnectionManager_AUTO,
		StatPrefix: "ingress",
		RouteSpecifier: &envoy_http_connection_manager.HttpConnectionManager_RouteConfig{
			RouteConfig: rc,
		},
		HttpFilters: filters,
		AccessLog:   buildAccessLogs(options),
		CommonHttpProtocolOptions: &envoy_config_core_v3.HttpProtocolOptions{
			IdleTimeout:       ptypes.DurationProto(options.IdleTimeout),
			MaxStreamDuration: maxStreamDuration,
		},
		RequestTimeout: ptypes.DurationProto(options.ReadTimeout),
		Tracing: &envoy_http_connection_manager.HttpConnectionManager_Tracing{
			RandomSampling: &envoy_type_v3.Percent{Value: options.TracingSampleRate * 100},
		},
		// See https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_conn_man/headers#x-forwarded-for
		UseRemoteAddress: &wrappers.BoolValue{Value: true},
		SkipXffAppend:    options.SkipXffAppend,
	})

	return &envoy_config_listener_v3.Filter{
		Name: "envoy.filters.network.http_connection_manager",
		ConfigType: &envoy_config_listener_v3.Filter_TypedConfig{
			TypedConfig: tc,
		},
	}, nil
}

func (srv *Server) buildGRPCListener(cfg *config.Config) (*envoy_config_listener_v3.Listener, error) {
	filter, err := srv.buildGRPCHTTPConnectionManagerFilter()
	if err != nil {
		return nil, err
	}

	if cfg.Options.GRPCInsecure {
		return &envoy_config_listener_v3.Listener{
			Name:    "grpc-ingress",
			Address: buildAddress(cfg.Options.GRPCAddr, 80),
			FilterChains: []*envoy_config_listener_v3.FilterChain{{
				Filters: []*envoy_config_listener_v3.Filter{
					filter,
				},
			}},
		}, nil
	}

	chains, err := srv.buildFilterChains(cfg.Options, cfg.Options.Addr,
		func(tlsDomain string, httpDomains []string) (*envoy_config_listener_v3.FilterChain, error) {
			filterChain := &envoy_config_listener_v3.FilterChain{
				Filters: []*envoy_config_listener_v3.Filter{filter},
			}
			if tlsDomain != "*" {
				filterChain.FilterChainMatch = &envoy_config_listener_v3.FilterChainMatch{
					ServerNames: []string{tlsDomain},
				}
			}
			tlsContext := srv.buildDownstreamTLSContext(cfg, tlsDomain)
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
	li := &envoy_config_listener_v3.Listener{
		Name:    "grpc-ingress",
		Address: buildAddress(cfg.Options.GRPCAddr, 443),
		ListenerFilters: []*envoy_config_listener_v3.ListenerFilter{{
			Name: "envoy.filters.listener.tls_inspector",
			ConfigType: &envoy_config_listener_v3.ListenerFilter_TypedConfig{
				TypedConfig: tlsInspectorCfg,
			},
		}},
		FilterChains: chains,
	}
	return li, nil
}

func (srv *Server) buildGRPCHTTPConnectionManagerFilter() (*envoy_config_listener_v3.Filter, error) {
	rc, err := srv.buildRouteConfiguration("grpc", []*envoy_config_route_v3.VirtualHost{{
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

func (srv *Server) buildRouteConfiguration(name string, virtualHosts []*envoy_config_route_v3.VirtualHost) (*envoy_config_route_v3.RouteConfiguration, error) {
	return &envoy_config_route_v3.RouteConfiguration{
		Name:         name,
		VirtualHosts: virtualHosts,
		// disable cluster validation since the order of LDS/CDS updates isn't guaranteed
		ValidateClusters: &wrappers.BoolValue{Value: false},
	}, nil
}

func (srv *Server) buildDownstreamTLSContext(cfg *config.Config, domain string) *envoy_extensions_transport_sockets_tls_v3.DownstreamTlsContext {
	cert, err := cryptutil.GetCertificateForDomain(cfg.AllCertificates(), domain)
	if err != nil {
		log.Warn().Str("domain", domain).Err(err).Msg("failed to get certificate for domain")
		return nil
	}

	envoyCert := srv.envoyTLSCertificateFromGoTLSCertificate(cert)
	return &envoy_extensions_transport_sockets_tls_v3.DownstreamTlsContext{
		CommonTlsContext: &envoy_extensions_transport_sockets_tls_v3.CommonTlsContext{
			TlsParams: &envoy_extensions_transport_sockets_tls_v3.TlsParameters{
				CipherSuites: []string{
					"ECDHE-ECDSA-AES256-GCM-SHA384",
					"ECDHE-RSA-AES256-GCM-SHA384",
					"ECDHE-ECDSA-AES128-GCM-SHA256",
					"ECDHE-RSA-AES128-GCM-SHA256",
					"ECDHE-ECDSA-CHACHA20-POLY1305",
					"ECDHE-RSA-CHACHA20-POLY1305",
				},
				TlsMinimumProtocolVersion: envoy_extensions_transport_sockets_tls_v3.TlsParameters_TLSv1_2,
			},
			TlsCertificates:       []*envoy_extensions_transport_sockets_tls_v3.TlsCertificate{envoyCert},
			AlpnProtocols:         []string{"h2", "http/1.1"},
			ValidationContextType: getDownstreamValidationContext(cfg, domain),
		},
	}
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
	authenticateURL, err := options.GetAuthenticateURL()
	if err != nil {
		return nil, err
	}

	authorizeURL, err := options.GetAuthorizeURL()
	if err != nil {
		return nil, err
	}

	dataBrokerURL, err := options.GetDataBrokerURL()
	if err != nil {
		return nil, err
	}

	forwardAuthURL, err := options.GetForwardAuthURL()
	if err != nil {
		return nil, err
	}

	lookup := map[string]struct{}{}
	if config.IsAuthenticate(options.Services) && addr == options.Addr {
		for _, h := range urlutil.GetDomainsForURL(*authenticateURL) {
			lookup[h] = struct{}{}
		}
	}
	if config.IsAuthorize(options.Services) && addr == options.GRPCAddr {
		for _, h := range urlutil.GetDomainsForURL(*authorizeURL) {
			lookup[h] = struct{}{}
		}
	}
	if config.IsDataBroker(options.Services) && addr == options.GRPCAddr {
		for _, h := range urlutil.GetDomainsForURL(*dataBrokerURL) {
			lookup[h] = struct{}{}
		}
	}
	if config.IsProxy(options.Services) && addr == options.Addr {
		for _, policy := range options.GetAllPolicies() {
			for _, h := range urlutil.GetDomainsForURL(*policy.Source.URL) {
				lookup[h] = struct{}{}
			}
		}
		if options.ForwardAuthURL != nil {
			for _, h := range urlutil.GetDomainsForURL(*forwardAuthURL) {
				lookup[h] = struct{}{}
			}
		}
	}

	domains := make([]string, 0, len(lookup))
	for domain := range lookup {
		domains = append(domains, domain)
	}
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

func hostMatchesDomain(u *url.URL, host string) bool {
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

func getDownstreamValidationContext(
	cfg *config.Config,
	domain string,
) *envoy_extensions_transport_sockets_tls_v3.CommonTlsContext_ValidationContext {
	needsClientCert := false

	if cfg.Options.ClientCA != "" {
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
	return &envoy_extensions_transport_sockets_tls_v3.CommonTlsContext_ValidationContext{
		ValidationContext: &envoy_extensions_transport_sockets_tls_v3.CertificateValidationContext{
			TrustChainVerification: envoy_extensions_transport_sockets_tls_v3.CertificateValidationContext_ACCEPT_UNTRUSTED,
		},
	}
}

func getPoliciesForDomain(options *config.Options, domain string) []config.Policy {
	var policies []config.Policy
	for _, p := range options.GetAllPolicies() {
		if p.Source != nil && hostMatchesDomain(p.Source.URL, domain) {
			policies = append(policies, p)
		}
	}
	return policies
}
