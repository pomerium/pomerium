package controlplane

import (
	"encoding/base64"
	"net"
	"net/url"
	"sort"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_listener_v3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_config_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoy_extensions_filters_http_ext_authz_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_authz/v3"
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

func (srv *Server) buildListeners(options *config.Options) []*envoy_config_listener_v3.Listener {
	var listeners []*envoy_config_listener_v3.Listener

	if config.IsAuthenticate(options.Services) || config.IsProxy(options.Services) {
		listeners = append(listeners, srv.buildMainListener(options))
	}

	if config.IsAuthorize(options.Services) || config.IsCache(options.Services) {
		listeners = append(listeners, srv.buildGRPCListener(options))
	}

	return listeners
}

func (srv *Server) buildMainListener(options *config.Options) *envoy_config_listener_v3.Listener {
	listenerFilters := []*envoy_config_listener_v3.ListenerFilter{}
	if options.UseProxyProtocol {
		proxyCfg := marshalAny(&envoy_extensions_filters_listener_proxy_protocol_v3.ProxyProtocol{})
		listenerFilters = append(listenerFilters, &envoy_config_listener_v3.ListenerFilter{
			Name: "envoy.filters.listener.proxy_protocol",
			ConfigType: &envoy_config_listener_v3.ListenerFilter_TypedConfig{
				TypedConfig: proxyCfg,
			},
		})
	}

	if options.InsecureServer {
		filter := buildMainHTTPConnectionManagerFilter(options,
			getAllRouteableDomains(options, options.Addr), "")

		return &envoy_config_listener_v3.Listener{
			Name:            "http-ingress",
			Address:         buildAddress(options.Addr, 80),
			ListenerFilters: listenerFilters,
			FilterChains: []*envoy_config_listener_v3.FilterChain{{
				Filters: []*envoy_config_listener_v3.Filter{
					filter,
				},
			}},
		}
	}

	tlsInspectorCfg := marshalAny(new(emptypb.Empty))
	listenerFilters = append(listenerFilters, &envoy_config_listener_v3.ListenerFilter{
		Name: "envoy.filters.listener.tls_inspector",
		ConfigType: &envoy_config_listener_v3.ListenerFilter_TypedConfig{
			TypedConfig: tlsInspectorCfg,
		},
	})

	li := &envoy_config_listener_v3.Listener{
		Name:            "https-ingress",
		Address:         buildAddress(options.Addr, 443),
		ListenerFilters: listenerFilters,
		FilterChains: buildFilterChains(options, options.Addr,
			func(tlsDomain string, httpDomains []string) *envoy_config_listener_v3.FilterChain {
				filter := buildMainHTTPConnectionManagerFilter(options, httpDomains, tlsDomain)
				filterChain := &envoy_config_listener_v3.FilterChain{
					Filters: []*envoy_config_listener_v3.Filter{filter},
				}
				if tlsDomain != "*" {
					filterChain.FilterChainMatch = &envoy_config_listener_v3.FilterChainMatch{
						ServerNames: []string{tlsDomain},
					}
				}
				tlsContext := srv.buildDownstreamTLSContext(options, tlsDomain)
				if tlsContext != nil {
					tlsConfig := marshalAny(tlsContext)
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
	tlsDomains := getAllTLSDomains(options, addr)
	var chains []*envoy_config_listener_v3.FilterChain
	for _, domain := range tlsDomains {
		// first we match on SNI
		chains = append(chains, callback(domain, []string{domain}))
	}
	// if there are no SNI matches we match on HTTP host
	chains = append(chains, callback("*", allDomains))
	return chains
}

func buildMainHTTPConnectionManagerFilter(options *config.Options, domains []string, tlsDomain string) *envoy_config_listener_v3.Filter {
	var virtualHosts []*envoy_config_route_v3.VirtualHost
	for _, domain := range domains {
		vh := &envoy_config_route_v3.VirtualHost{
			Name:    domain,
			Domains: []string{domain},
		}

		if options.Addr == options.GRPCAddr {
			// if this is a gRPC service domain and we're supposed to handle that, add those routes
			if (config.IsAuthorize(options.Services) && hostMatchesDomain(options.GetAuthorizeURL(), domain)) ||
				(config.IsCache(options.Services) && hostMatchesDomain(options.GetDataBrokerURL(), domain)) {
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
	if tlsDomain == "*" {
		virtualHosts = append(virtualHosts, &envoy_config_route_v3.VirtualHost{
			Name:    "catch-all",
			Domains: []string{"*"},
			Routes:  buildPomeriumHTTPRoutes(options, "*"),
		})
	}

	var maxStreamDuration *durationpb.Duration
	if options.WriteTimeout > 0 {
		maxStreamDuration = ptypes.DurationProto(options.WriteTimeout)
	}

	tc := marshalAny(&envoy_http_connection_manager.HttpConnectionManager{
		CodecType:  envoy_http_connection_manager.HttpConnectionManager_AUTO,
		StatPrefix: "ingress",
		RouteSpecifier: &envoy_http_connection_manager.HttpConnectionManager_RouteConfig{
			RouteConfig: buildRouteConfiguration("main", virtualHosts),
		},
		HttpFilters: getHTTPConnectionManagerFilters(options, tlsDomain),
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
		SkipXffAppend:    false,
	})

	return &envoy_config_listener_v3.Filter{
		Name: "envoy.filters.network.http_connection_manager",
		ConfigType: &envoy_config_listener_v3.Filter_TypedConfig{
			TypedConfig: tc,
		},
	}
}

func (srv *Server) buildGRPCListener(options *config.Options) *envoy_config_listener_v3.Listener {
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

	tlsInspectorCfg := marshalAny(new(emptypb.Empty))
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
				tlsContext := srv.buildDownstreamTLSContext(options, tlsDomain)
				if tlsContext != nil {
					tlsConfig := marshalAny(tlsContext)
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
	tc := marshalAny(&envoy_http_connection_manager.HttpConnectionManager{
		CodecType:  envoy_http_connection_manager.HttpConnectionManager_AUTO,
		StatPrefix: "grpc_ingress",
		// limit request first byte to last byte time
		RequestTimeout: &durationpb.Duration{
			Seconds: 15,
		},
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

func (srv *Server) buildDownstreamTLSContext(options *config.Options, domain string) *envoy_extensions_transport_sockets_tls_v3.DownstreamTlsContext {
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
		trustedCA = srv.filemgr.BytesDataSource("client-ca", bs)
	} else if options.ClientCAFile != "" {
		trustedCA = srv.filemgr.FileDataSource(options.ClientCAFile)
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
			ValidationContextType: validationContext,
		},
	}
}

func getAllRouteableDomains(options *config.Options, addr string) []string {
	lookup := map[string]struct{}{}
	if config.IsAuthenticate(options.Services) && addr == options.Addr {
		for _, h := range urlutil.GetDomainsForURL(options.GetAuthenticateURL()) {
			lookup[h] = struct{}{}
		}
	}
	if config.IsAuthorize(options.Services) && addr == options.GRPCAddr {
		for _, h := range urlutil.GetDomainsForURL(options.GetAuthorizeURL()) {
			lookup[h] = struct{}{}
		}
	}
	if config.IsCache(options.Services) && addr == options.GRPCAddr {
		for _, h := range urlutil.GetDomainsForURL(options.GetDataBrokerURL()) {
			lookup[h] = struct{}{}
		}
	}
	if config.IsProxy(options.Services) && addr == options.Addr {
		for _, policy := range options.Policies {
			for _, h := range urlutil.GetDomainsForURL(policy.Source.URL) {
				lookup[h] = struct{}{}
			}
		}
		if options.ForwardAuthURL != nil {
			for _, h := range urlutil.GetDomainsForURL(options.GetForwardAuthURL()) {
				lookup[h] = struct{}{}
			}
		}
	}

	domains := make([]string, 0, len(lookup))
	for domain := range lookup {
		domains = append(domains, domain)
	}
	sort.Strings(domains)

	return domains
}

func getAllTLSDomains(options *config.Options, addr string) []string {
	lookup := map[string]struct{}{}
	for _, hp := range getAllRouteableDomains(options, addr) {
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

	return domains
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
