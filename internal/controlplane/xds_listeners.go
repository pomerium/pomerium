package controlplane

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
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
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/cryptutil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/urlutil"
)

var disableExtAuthz *any.Any

func init() {
	disableExtAuthz, _ = ptypes.MarshalAny(&envoy_extensions_filters_http_ext_authz_v3.ExtAuthzPerRoute{
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
	if options.InsecureServer {
		filter := srv.buildMainHTTPConnectionManagerFilter(options,
			srv.getAllRouteableDomains(options, options.Addr))

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
		FilterChains: srv.buildFilterChains(options, options.Addr,
			func(tlsDomain string, httpDomains []string) *envoy_config_listener_v3.FilterChain {
				filter := srv.buildMainHTTPConnectionManagerFilter(options, httpDomains)
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

func (srv *Server) buildFilterChains(
	options *config.Options, addr string,
	callback func(tlsDomain string, httpDomains []string) *envoy_config_listener_v3.FilterChain,
) []*envoy_config_listener_v3.FilterChain {
	allDomains := srv.getAllRouteableDomains(options, addr)
	var chains []*envoy_config_listener_v3.FilterChain
	for _, domain := range allDomains {
		// first we match on SNI
		chains = append(chains, callback(domain, allDomains))
	}
	// if there are no SNI matches we match on HTTP host
	chains = append(chains, callback("*", allDomains))
	return chains
}

func (srv *Server) buildMainHTTPConnectionManagerFilter(options *config.Options, domains []string) *envoy_config_listener_v3.Filter {
	var virtualHosts []*envoy_config_route_v3.VirtualHost
	for _, domain := range domains {
		vh := &envoy_config_route_v3.VirtualHost{
			Name:    domain,
			Domains: []string{domain},
		}

		if options.Addr == options.GRPCAddr {
			// if this is a gRPC service domain and we're supposed to handle that, add those routes
			if (config.IsAuthorize(options.Services) && domain == urlutil.StripPort(options.AuthorizeURL.Host)) ||
				(config.IsCache(options.Services) && domain == urlutil.StripPort(options.CacheURL.Host)) {
				vh.Routes = append(vh.Routes, srv.buildGRPCRoutes()...)
			}
		}

		// these routes match /.pomerium/... and similar paths
		vh.Routes = append(vh.Routes, srv.buildPomeriumHTTPRoutes(options, domain)...)

		// if we're the proxy, add all the policy routes
		if config.IsProxy(options.Services) {
			vh.Routes = append(vh.Routes, srv.buildPolicyRoutes(options, domain)...)
		}

		if len(vh.Routes) > 0 {
			virtualHosts = append(virtualHosts, vh)
		}
	}

	extAuthZ, _ := ptypes.MarshalAny(&envoy_extensions_filters_http_ext_authz_v3.ExtAuthz{
		StatusOnError: &envoy_type_v3.HttpStatus{
			Code: envoy_type_v3.StatusCode_InternalServerError,
		},
		Services: &envoy_extensions_filters_http_ext_authz_v3.ExtAuthz_GrpcService{
			GrpcService: &envoy_config_core_v3.GrpcService{
				Timeout: ptypes.DurationProto(time.Second * 30),
				TargetSpecifier: &envoy_config_core_v3.GrpcService_EnvoyGrpc_{
					EnvoyGrpc: &envoy_config_core_v3.GrpcService_EnvoyGrpc{
						ClusterName: "pomerium-authz",
					},
				},
			},
		},
	})

	extAuthzSetCookieLua, _ := ptypes.MarshalAny(&envoy_extensions_filters_http_lua_v3.Lua{
		InlineCode: luascripts.ExtAuthzSetCookie,
	})
	cleanUpstreamLua, _ := ptypes.MarshalAny(&envoy_extensions_filters_http_lua_v3.Lua{
		InlineCode: luascripts.CleanUpstream,
	})

	tc, _ := ptypes.MarshalAny(&envoy_http_connection_manager.HttpConnectionManager{
		CodecType:  envoy_http_connection_manager.HttpConnectionManager_AUTO,
		StatPrefix: "ingress",
		RouteSpecifier: &envoy_http_connection_manager.HttpConnectionManager_RouteConfig{
			RouteConfig: &envoy_config_route_v3.RouteConfiguration{
				Name:         "main",
				VirtualHosts: virtualHosts,
			},
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
		AccessLog: srv.buildAccessLogs(options),
	})

	return &envoy_config_listener_v3.Filter{
		Name: "envoy.filters.network.http_connection_manager",
		ConfigType: &envoy_config_listener_v3.Filter_TypedConfig{
			TypedConfig: tc,
		},
	}
}

func (srv *Server) buildGRPCListener(options *config.Options) *envoy_config_listener_v3.Listener {
	filter := srv.buildGRPCHTTPConnectionManagerFilter()

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
		FilterChains: srv.buildFilterChains(options, options.Addr,
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

func (srv *Server) buildGRPCHTTPConnectionManagerFilter() *envoy_config_listener_v3.Filter {
	tc, _ := ptypes.MarshalAny(&envoy_http_connection_manager.HttpConnectionManager{
		CodecType:  envoy_http_connection_manager.HttpConnectionManager_AUTO,
		StatPrefix: "grpc_ingress",
		RouteSpecifier: &envoy_http_connection_manager.HttpConnectionManager_RouteConfig{
			RouteConfig: &envoy_config_route_v3.RouteConfiguration{
				Name: "grpc",
				VirtualHosts: []*envoy_config_route_v3.VirtualHost{{
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
				}},
			},
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

func (srv *Server) buildDownstreamTLSContext(options *config.Options, domain string) *envoy_extensions_transport_sockets_tls_v3.DownstreamTlsContext {
	cert, err := cryptutil.GetCertificateForDomain(options.Certificates, domain)
	if err != nil {
		log.Warn().Str("domain", domain).Err(err).Msg("failed to get certificate for domain")
		return nil
	}

	envoyCert := &envoy_extensions_transport_sockets_tls_v3.TlsCertificate{}
	var chain bytes.Buffer
	for _, cbs := range cert.Certificate {
		_ = pem.Encode(&chain, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cbs,
		})
	}
	envoyCert.CertificateChain = inlineBytes(chain.Bytes())
	if cert.OCSPStaple != nil {
		envoyCert.OcspStaple = inlineBytes(cert.OCSPStaple)
	}
	if bs, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey); err == nil {
		envoyCert.PrivateKey = inlineBytes(pem.EncodeToMemory(
			&pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: bs,
			},
		))
	} else {
		log.Warn().Err(err).Msg("failed to marshal private key for tls config")
	}
	for _, scts := range cert.SignedCertificateTimestamps {
		envoyCert.SignedCertificateTimestamp = append(envoyCert.SignedCertificateTimestamp,
			inlineBytes(scts))
	}

	return &envoy_extensions_transport_sockets_tls_v3.DownstreamTlsContext{
		CommonTlsContext: &envoy_extensions_transport_sockets_tls_v3.CommonTlsContext{
			TlsCertificates: []*envoy_extensions_transport_sockets_tls_v3.TlsCertificate{envoyCert},
			AlpnProtocols:   []string{"h2", "http/1.1"},
		},
	}
}

func (srv *Server) getAllRouteableDomains(options *config.Options, addr string) []string {
	lookup := map[string]struct{}{}
	if config.IsAuthenticate(options.Services) && addr == options.Addr {
		lookup[urlutil.StripPort(options.AuthenticateURL.Host)] = struct{}{}
	}
	if config.IsAuthorize(options.Services) && addr == options.GRPCAddr {
		lookup[urlutil.StripPort(options.AuthorizeURL.Host)] = struct{}{}
	}
	if config.IsCache(options.Services) && addr == options.GRPCAddr {
		lookup[urlutil.StripPort(options.CacheURL.Host)] = struct{}{}
	}
	if config.IsProxy(options.Services) && addr == options.Addr {
		for _, policy := range options.Policies {
			lookup[urlutil.StripPort(policy.Source.Host)] = struct{}{}
		}
		if options.ForwardAuthURL != nil {
			lookup[urlutil.StripPort(options.ForwardAuthURL.Host)] = struct{}{}
		}
	}

	domains := make([]string, 0, len(lookup))
	for domain := range lookup {
		domains = append(domains, domain)
	}
	sort.Strings(domains)

	return domains
}
