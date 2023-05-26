package envoyconfig

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"time"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_listener_v3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_config_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoy_http_connection_manager "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	envoy_extensions_transport_sockets_tls_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	envoy_type_v3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/golang/protobuf/ptypes/wrappers"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/hashutil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/sets"
	"github.com/pomerium/pomerium/internal/telemetry/metrics"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
)

const listenerBufferLimit uint32 = 32 * 1024

var tlsParams = &envoy_extensions_transport_sockets_tls_v3.TlsParameters{
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

	if cfg.Options.EnvoyAdminAddress != "" {
		li, err := b.buildEnvoyAdminListener(ctx, cfg)
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
	li := newEnvoyListener("http-ingress")
	if cfg.Options.UseProxyProtocol {
		li.ListenerFilters = append(li.ListenerFilters, ProxyProtocolFilter())
	}

	if cfg.Options.InsecureServer {
		li.Address = buildAddress(cfg.Options.Addr, 80)

		filter, err := b.buildMainHTTPConnectionManagerFilter(cfg.Options, false)
		if err != nil {
			return nil, err
		}

		li.FilterChains = []*envoy_config_listener_v3.FilterChain{{
			Filters: []*envoy_config_listener_v3.Filter{
				filter,
			},
		}}
	} else {
		li.Address = buildAddress(cfg.Options.Addr, 443)
		li.ListenerFilters = append(li.ListenerFilters, TLSInspectorFilter())

		allCertificates, _ := cfg.AllCertificates()

		serverNames, err := getAllServerNames(cfg, cfg.Options.Addr)
		if err != nil {
			return nil, err
		}

		for _, serverName := range serverNames {
			requireStrictTransportSecurity := cryptutil.HasCertificateForServerName(allCertificates, serverName)
			filter, err := b.buildMainHTTPConnectionManagerFilter(cfg.Options, requireStrictTransportSecurity)
			if err != nil {
				return nil, err
			}
			filterChain := &envoy_config_listener_v3.FilterChain{
				Filters: []*envoy_config_listener_v3.Filter{filter},
			}
			if serverName != "*" {
				filterChain.FilterChainMatch = &envoy_config_listener_v3.FilterChainMatch{
					ServerNames: []string{serverName},
				}
			}
			tlsContext := b.buildDownstreamTLSContext(ctx, cfg, serverName)
			if tlsContext != nil {
				tlsConfig := marshalAny(tlsContext)
				filterChain.TransportSocket = &envoy_config_core_v3.TransportSocket{
					Name: "tls",
					ConfigType: &envoy_config_core_v3.TransportSocket_TypedConfig{
						TypedConfig: tlsConfig,
					},
				}
			}
			li.FilterChains = append(li.FilterChains, filterChain)
		}
	}
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

	addr := buildAddress(net.JoinHostPort(host, port), 9902)
	li := newEnvoyListener(fmt.Sprintf("metrics-ingress-%d", hashutil.MustHash(addr)))
	li.Address = addr
	li.FilterChains = []*envoy_config_listener_v3.FilterChain{filterChain}
	return li, nil
}

func (b *Builder) buildMainHTTPConnectionManagerFilter(
	options *config.Options,
	requireStrictTransportSecurity bool,
) (*envoy_config_listener_v3.Filter, error) {
	authorizeURLs, err := options.GetInternalAuthorizeURLs()
	if err != nil {
		return nil, err
	}

	dataBrokerURLs, err := options.GetInternalDataBrokerURLs()
	if err != nil {
		return nil, err
	}

	allHosts, err := getAllRouteableHosts(options, options.Addr)
	if err != nil {
		return nil, err
	}

	var virtualHosts []*envoy_config_route_v3.VirtualHost
	for _, host := range allHosts {
		vh, err := b.buildVirtualHost(options, host, host, requireStrictTransportSecurity)
		if err != nil {
			return nil, err
		}

		if options.Addr == options.GetGRPCAddr() {
			// if this is a gRPC service domain and we're supposed to handle that, add those routes
			if (config.IsAuthorize(options.Services) && urlsMatchHost(authorizeURLs, host)) ||
				(config.IsDataBroker(options.Services) && urlsMatchHost(dataBrokerURLs, host)) {
				rs, err := b.buildGRPCRoutes()
				if err != nil {
					return nil, err
				}
				vh.Routes = append(vh.Routes, rs...)
			}
		}

		// if we're the proxy, add all the policy routes
		if config.IsProxy(options.Services) {
			rs, err := b.buildPolicyRoutes(options, host)
			if err != nil {
				return nil, err
			}
			vh.Routes = append(vh.Routes, rs...)
		}

		if len(vh.Routes) > 0 {
			virtualHosts = append(virtualHosts, vh)
		}
	}

	vh, err := b.buildVirtualHost(options, "catch-all", "*", requireStrictTransportSecurity)
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

	filters := []*envoy_http_connection_manager.HttpFilter{
		LuaFilter(luascripts.RemoveImpersonateHeaders),
		ExtAuthzFilter(grpcClientTimeout),
		LuaFilter(luascripts.ExtAuthzSetCookie),
		LuaFilter(luascripts.CleanUpstream),
		LuaFilter(luascripts.RewriteHeaders),
	}
	filters = append(filters, HTTPRouterFilter())

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

	return HTTPConnectionManagerFilter(&envoy_http_connection_manager.HttpConnectionManager{
		AlwaysSetRequestIdInResponse: true,

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
		LocalReplyConfig:  b.buildLocalReplyConfig(options, requireStrictTransportSecurity),
		NormalizePath:     wrapperspb.Bool(true),
	}), nil
}

func (b *Builder) buildMetricsHTTPConnectionManagerFilter() (*envoy_config_listener_v3.Filter, error) {
	rc, err := b.buildRouteConfiguration("metrics", []*envoy_config_route_v3.VirtualHost{{
		Name:    "metrics",
		Domains: []string{"*"},
		Routes: []*envoy_config_route_v3.Route{
			{
				Name: "envoy-metrics",
				Match: &envoy_config_route_v3.RouteMatch{
					PathSpecifier: &envoy_config_route_v3.RouteMatch_Prefix{Prefix: metrics.EnvoyMetricsPath},
				},
				Action: &envoy_config_route_v3.Route_Route{
					Route: &envoy_config_route_v3.RouteAction{
						ClusterSpecifier: &envoy_config_route_v3.RouteAction_Cluster{
							Cluster: envoyAdminClusterName,
						},
						PrefixRewrite: "/stats/prometheus",
					},
				},
			},
			{
				Name: "metrics",
				Match: &envoy_config_route_v3.RouteMatch{
					PathSpecifier: &envoy_config_route_v3.RouteMatch_Prefix{Prefix: "/"},
				},
				Action: &envoy_config_route_v3.Route_Route{
					Route: &envoy_config_route_v3.RouteAction{
						ClusterSpecifier: &envoy_config_route_v3.RouteAction_Cluster{
							Cluster: "pomerium-control-plane-metrics",
						},
					},
				},
			},
		},
	}})
	if err != nil {
		return nil, err
	}

	return HTTPConnectionManagerFilter(&envoy_http_connection_manager.HttpConnectionManager{
		CodecType:  envoy_http_connection_manager.HttpConnectionManager_AUTO,
		StatPrefix: "metrics",
		RouteSpecifier: &envoy_http_connection_manager.HttpConnectionManager_RouteConfig{
			RouteConfig: rc,
		},
		HttpFilters: []*envoy_http_connection_manager.HttpFilter{
			HTTPRouterFilter(),
		},
	}), nil
}

func (b *Builder) buildGRPCListener(ctx context.Context, cfg *config.Config) (*envoy_config_listener_v3.Listener, error) {
	filter, err := b.buildGRPCHTTPConnectionManagerFilter()
	if err != nil {
		return nil, err
	}

	li := newEnvoyListener("grpc-ingress")
	if cfg.Options.GetGRPCInsecure() {
		li.Address = buildAddress(cfg.Options.GetGRPCAddr(), 80)
		li.FilterChains = []*envoy_config_listener_v3.FilterChain{{
			Filters: []*envoy_config_listener_v3.Filter{
				filter,
			},
		}}
	} else {
		li.Address = buildAddress(cfg.Options.GetGRPCAddr(), 443)
		li.ListenerFilters = []*envoy_config_listener_v3.ListenerFilter{
			TLSInspectorFilter(),
		}

		serverNames, err := getAllServerNames(cfg, cfg.Options.GRPCAddr)
		if err != nil {
			return nil, err
		}

		for _, serverName := range serverNames {
			filterChain := &envoy_config_listener_v3.FilterChain{
				Filters: []*envoy_config_listener_v3.Filter{filter},
			}
			if serverName != "*" {
				filterChain.FilterChainMatch = &envoy_config_listener_v3.FilterChainMatch{
					ServerNames: []string{serverName},
				}
			}
			tlsContext := b.buildDownstreamTLSContext(ctx, cfg, serverName)
			if tlsContext != nil {
				tlsConfig := marshalAny(tlsContext)
				filterChain.TransportSocket = &envoy_config_core_v3.TransportSocket{
					Name: "tls",
					ConfigType: &envoy_config_core_v3.TransportSocket_TypedConfig{
						TypedConfig: tlsConfig,
					},
				}
			}
			li.FilterChains = append(li.FilterChains, filterChain)
		}
	}
	return li, nil
}

func (b *Builder) buildGRPCHTTPConnectionManagerFilter() (*envoy_config_listener_v3.Filter, error) {
	allow := []string{
		"envoy.service.auth.v3.Authorization",
		"databroker.DataBrokerService",
		"registry.Registry",
		"grpc.health.v1.Health",
	}
	routes := make([]*envoy_config_route_v3.Route, 0, len(allow))
	for _, svc := range allow {
		routes = append(routes, &envoy_config_route_v3.Route{
			Name: "grpc",
			Match: &envoy_config_route_v3.RouteMatch{
				PathSpecifier: &envoy_config_route_v3.RouteMatch_Prefix{Prefix: fmt.Sprintf("/%s/", svc)},
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
		})
	}
	rc, err := b.buildRouteConfiguration("grpc", []*envoy_config_route_v3.VirtualHost{{
		Name:    "grpc",
		Domains: []string{"*"},
		Routes:  routes,
	}})
	if err != nil {
		return nil, err
	}

	return HTTPConnectionManagerFilter(&envoy_http_connection_manager.HttpConnectionManager{
		CodecType:  envoy_http_connection_manager.HttpConnectionManager_AUTO,
		StatPrefix: "grpc_ingress",
		// limit request first byte to last byte time
		RequestTimeout: &durationpb.Duration{
			Seconds: 15,
		},
		RouteSpecifier: &envoy_http_connection_manager.HttpConnectionManager_RouteConfig{
			RouteConfig: rc,
		},
		HttpFilters: []*envoy_http_connection_manager.HttpFilter{
			HTTPRouterFilter(),
		},
	}), nil
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
	serverName string,
) *envoy_extensions_transport_sockets_tls_v3.DownstreamTlsContext {
	cert, err := cfg.GetCertificateForServerName(serverName)
	if err != nil {
		log.Warn(ctx).Str("domain", serverName).Err(err).Msg("failed to get certificate for domain")
		return nil
	}

	err = validateCertificate(cert)
	if err != nil {
		log.Warn(ctx).Str("domain", serverName).Err(err).Msg("invalid certificate for domain")
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
			ValidationContextType: b.buildDownstreamValidationContext(ctx, cfg, serverName),
		},
	}
}

func (b *Builder) buildDownstreamValidationContext(ctx context.Context,
	cfg *config.Config,
	serverName string,
) *envoy_extensions_transport_sockets_tls_v3.CommonTlsContext_ValidationContext {
	needsClientCert := false

	if ca, _ := cfg.Options.GetClientCA(); len(ca) > 0 {
		needsClientCert = true
	}
	if !needsClientCert {
		for _, p := range getPoliciesForServerName(cfg.Options, serverName) {
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

func getAllRouteableHosts(options *config.Options, addr string) ([]string, error) {
	allHosts := sets.NewSorted[string]()

	if addr == options.Addr {
		hosts, err := options.GetAllRouteableHTTPHosts()
		if err != nil {
			return nil, err
		}
		allHosts.Add(hosts...)
	}

	if addr == options.GetGRPCAddr() {
		hosts, err := options.GetAllRouteableGRPCHosts()
		if err != nil {
			return nil, err
		}
		allHosts.Add(hosts...)
	}

	return allHosts.ToSlice(), nil
}

func getAllServerNames(cfg *config.Config, addr string) ([]string, error) {
	serverNames := sets.NewSorted[string]()
	serverNames.Add("*")

	certs, err := cfg.AllCertificates()
	if err != nil {
		return nil, err
	}
	for i := range certs {
		serverNames.Add(cryptutil.GetCertificateServerNames(&certs[i])...)
	}

	if addr == cfg.Options.Addr {
		sns, err := cfg.Options.GetAllRouteableHTTPServerNames()
		if err != nil {
			return nil, err
		}
		serverNames.Add(sns...)
	}

	if addr == cfg.Options.GetGRPCAddr() {
		sns, err := cfg.Options.GetAllRouteableGRPCServerNames()
		if err != nil {
			return nil, err
		}
		serverNames.Add(sns...)
	}

	return serverNames.ToSlice(), nil
}

func urlsMatchHost(urls []*url.URL, host string) bool {
	for _, u := range urls {
		if urlMatchesHost(u, host) {
			return true
		}
	}
	return false
}

func urlMatchesHost(u *url.URL, host string) bool {
	for _, h := range urlutil.GetDomainsForURL(u) {
		if h == host {
			return true
		}
	}
	return false
}

func getPoliciesForServerName(options *config.Options, serverName string) []config.Policy {
	var policies []config.Policy
	for _, p := range options.GetAllPolicies() {
		if p.Source != nil && urlutil.MatchesServerName(*p.Source.URL, serverName) {
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
