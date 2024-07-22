package envoyconfig

import (
	"bytes"
	"cmp"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"runtime"
	"time"

	envoy_config_accesslog_v3 "github.com/envoyproxy/go-control-plane/envoy/config/accesslog/v3"
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_listener_v3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_config_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoy_extensions_access_loggers_grpc_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/grpc/v3"
	envoy_http_connection_manager "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	envoy_extensions_transport_sockets_tls_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	envoy_type_v3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/hashicorp/go-set/v3"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/hashutil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry/metrics"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
	"github.com/pomerium/pomerium/internal/urlutil"
)

const listenerBufferLimit uint32 = 32 * 1024

// BuildListeners builds envoy listeners from the given config.
func (b *Builder) BuildListeners(
	ctx context.Context,
	fullyStatic bool,
) ([]*envoy_config_listener_v3.Listener, error) {
	ctx, span := trace.StartSpan(ctx, "envoyconfig.Builder.BuildListeners")
	defer span.End()

	var listeners []*envoy_config_listener_v3.Listener

	if shouldStartMainListener(b.cfg.Options) {
		li, err := b.buildMainListener(ctx, fullyStatic)
		if err != nil {
			return nil, err
		}
		listeners = append(listeners, li)
	}

	if shouldStartGRPCListener(b.cfg.Options) {
		li, err := b.buildGRPCListener(ctx)
		if err != nil {
			return nil, err
		}
		listeners = append(listeners, li)
	}

	if b.cfg.Options.MetricsAddr != "" {
		li, err := b.buildMetricsListener(ctx)
		if err != nil {
			return nil, err
		}
		listeners = append(listeners, li)
	}

	if b.cfg.Options.EnvoyAdminAddress != "" {
		li, err := b.buildEnvoyAdminListener()
		if err != nil {
			return nil, err
		}
		listeners = append(listeners, li)
	}

	li, err := b.buildOutboundListener()
	if err != nil {
		return nil, err
	}
	listeners = append(listeners, li)

	return listeners, nil
}

func getAllCertificates(cfg *config.Config) ([]tls.Certificate, error) {
	allCertificates, err := cfg.AllCertificates()
	if err != nil {
		return nil, fmt.Errorf("error collecting all certificates: %w", err)
	}

	wc, err := cfg.GenerateCatchAllCertificate()
	if err != nil {
		return nil, fmt.Errorf("error getting wildcard certificate: %w", err)
	}

	return append(allCertificates, *wc), nil
}

func (b *Builder) buildTLSSocket(ctx context.Context, certs []tls.Certificate) (*envoy_config_core_v3.TransportSocket, error) {
	tlsContext, err := b.buildDownstreamTLSContextMulti(ctx, certs)
	if err != nil {
		return nil, err
	}
	return &envoy_config_core_v3.TransportSocket{
		Name: "tls",
		ConfigType: &envoy_config_core_v3.TransportSocket_TypedConfig{
			TypedConfig: marshalAny(tlsContext),
		},
	}, nil
}

func listenerAccessLog() []*envoy_config_accesslog_v3.AccessLog {
	cc := &envoy_extensions_access_loggers_grpc_v3.CommonGrpcAccessLogConfig{
		LogName: "ingress-http-listener",
		GrpcService: &envoy_config_core_v3.GrpcService{
			TargetSpecifier: &envoy_config_core_v3.GrpcService_EnvoyGrpc_{
				EnvoyGrpc: &envoy_config_core_v3.GrpcService_EnvoyGrpc{
					ClusterName: "pomerium-control-plane-grpc",
				},
			},
		},
		TransportApiVersion: envoy_config_core_v3.ApiVersion_V3,
	}
	tcp := marshalAny(
		&envoy_extensions_access_loggers_grpc_v3.TcpGrpcAccessLogConfig{CommonConfig: cc})
	return []*envoy_config_accesslog_v3.AccessLog{
		{
			Name:       "envoy.access_loggers.tcp_grpc",
			ConfigType: &envoy_config_accesslog_v3.AccessLog_TypedConfig{TypedConfig: tcp},
		},
	}
}

func (b *Builder) buildMainListener(
	ctx context.Context,
	fullyStatic bool,
) (*envoy_config_listener_v3.Listener, error) {
	li := newEnvoyListener("http-ingress")
	if b.cfg.Options.UseProxyProtocol {
		li.ListenerFilters = append(li.ListenerFilters, ProxyProtocolFilter())
	}

	if b.cfg.Options.DownstreamMTLS.Enforcement == config.MTLSEnforcementRejectConnection {
		li.AccessLog = listenerAccessLog()
	}

	if b.cfg.Options.InsecureServer {
		li.Address = buildAddress(b.cfg.Options.Addr, 80)

		filter, err := b.buildMainHTTPConnectionManagerFilter(fullyStatic)
		if err != nil {
			return nil, err
		}

		li.FilterChains = []*envoy_config_listener_v3.FilterChain{{
			Filters: []*envoy_config_listener_v3.Filter{
				filter,
			},
		}}
	} else {
		li.Address = buildAddress(b.cfg.Options.Addr, 443)
		li.ListenerFilters = append(li.ListenerFilters, TLSInspectorFilter())

		li.FilterChains = append(li.FilterChains, b.buildACMETLSALPNFilterChain())

		allCertificates, err := getAllCertificates(b.cfg)
		if err != nil {
			return nil, err
		}

		filter, err := b.buildMainHTTPConnectionManagerFilter(fullyStatic)
		if err != nil {
			return nil, err
		}
		filterChain := &envoy_config_listener_v3.FilterChain{
			Filters: []*envoy_config_listener_v3.Filter{filter},
		}
		li.FilterChains = append(li.FilterChains, filterChain)

		sock, err := b.buildTLSSocket(ctx, allCertificates)
		if err != nil {
			return nil, fmt.Errorf("error building TLS socket: %w", err)
		}
		filterChain.TransportSocket = sock
	}
	return li, nil
}

func (b *Builder) buildMetricsListener(ctx context.Context) (*envoy_config_listener_v3.Listener, error) {
	filter, err := b.buildMetricsHTTPConnectionManagerFilter()
	if err != nil {
		return nil, err
	}

	filterChain := &envoy_config_listener_v3.FilterChain{
		Filters: []*envoy_config_listener_v3.Filter{
			filter,
		},
	}

	cert, err := b.cfg.Options.GetMetricsCertificate()
	if err != nil {
		return nil, err
	}
	if cert != nil {
		dtc := &envoy_extensions_transport_sockets_tls_v3.DownstreamTlsContext{
			CommonTlsContext: &envoy_extensions_transport_sockets_tls_v3.CommonTlsContext{
				TlsParams: tlsDownstreamParams,
				TlsCertificates: []*envoy_extensions_transport_sockets_tls_v3.TlsCertificate{
					b.envoyTLSCertificateFromGoTLSCertificate(ctx, cert),
				},
				AlpnProtocols: []string{"h2", "http/1.1"},
			},
		}

		if b.cfg.Options.MetricsClientCA != "" {
			bs, err := base64.StdEncoding.DecodeString(b.cfg.Options.MetricsClientCA)
			if err != nil {
				return nil, fmt.Errorf("xds: invalid metrics_client_ca: %w", err)
			}

			dtc.RequireClientCertificate = wrapperspb.Bool(true)
			dtc.CommonTlsContext.ValidationContextType = &envoy_extensions_transport_sockets_tls_v3.CommonTlsContext_ValidationContext{
				ValidationContext: &envoy_extensions_transport_sockets_tls_v3.CertificateValidationContext{
					TrustChainVerification: envoy_extensions_transport_sockets_tls_v3.CertificateValidationContext_VERIFY_TRUST_CHAIN,
					TrustedCa:              b.opts.FileManager.BytesDataSource("metrics_client_ca.pem", bs),
				},
			}
		} else if b.cfg.Options.MetricsClientCAFile != "" {
			dtc.RequireClientCertificate = wrapperspb.Bool(true)
			dtc.CommonTlsContext.ValidationContextType = &envoy_extensions_transport_sockets_tls_v3.CommonTlsContext_ValidationContext{
				ValidationContext: &envoy_extensions_transport_sockets_tls_v3.CertificateValidationContext{
					TrustChainVerification: envoy_extensions_transport_sockets_tls_v3.CertificateValidationContext_VERIFY_TRUST_CHAIN,
					TrustedCa:              b.opts.FileManager.FileDataSource(b.cfg.Options.MetricsClientCAFile),
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
	host, port, err := net.SplitHostPort(b.cfg.Options.MetricsAddr)
	if err != nil {
		return nil, fmt.Errorf("metrics_addr %s: %w", b.cfg.Options.MetricsAddr, err)
	}
	if port == "" {
		return nil, fmt.Errorf("metrics_addr %s: port is required", b.cfg.Options.MetricsAddr)
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
	fullyStatic bool,
) (*envoy_config_listener_v3.Filter, error) {
	var grpcClientTimeout *durationpb.Duration
	if b.cfg.Options.GRPCClientTimeout != 0 {
		grpcClientTimeout = durationpb.New(b.cfg.Options.GRPCClientTimeout)
	} else {
		grpcClientTimeout = durationpb.New(30 * time.Second)
	}

	filters := []*envoy_http_connection_manager.HttpFilter{
		LuaFilter(luascripts.RemoveImpersonateHeaders),
		LuaFilter(luascripts.SetClientCertificateMetadata),
		ExtAuthzFilter(grpcClientTimeout),
		LuaFilter(luascripts.ExtAuthzSetCookie),
		LuaFilter(luascripts.CleanUpstream),
		LuaFilter(luascripts.RewriteHeaders),
	}
	filters = append(filters, HTTPRouterFilter())

	var maxStreamDuration *durationpb.Duration
	if b.cfg.Options.WriteTimeout > 0 {
		maxStreamDuration = durationpb.New(b.cfg.Options.WriteTimeout)
	}

	tracingProvider, err := buildTracingHTTP(b.cfg.Options)
	if err != nil {
		return nil, err
	}

	localReply, err := b.buildLocalReplyConfig()
	if err != nil {
		return nil, err
	}

	mgr := &envoy_http_connection_manager.HttpConnectionManager{
		AlwaysSetRequestIdInResponse: true,
		CodecType:                    b.cfg.Options.GetCodecType().ToEnvoy(),
		StatPrefix:                   "ingress",
		HttpFilters:                  filters,
		AccessLog:                    buildAccessLogs(b.cfg.Options),
		CommonHttpProtocolOptions: &envoy_config_core_v3.HttpProtocolOptions{
			IdleTimeout:       durationpb.New(b.cfg.Options.IdleTimeout),
			MaxStreamDuration: maxStreamDuration,
		},
		HttpProtocolOptions: http1ProtocolOptions,
		RequestTimeout:      durationpb.New(b.cfg.Options.ReadTimeout),
		Tracing: &envoy_http_connection_manager.HttpConnectionManager_Tracing{
			RandomSampling: &envoy_type_v3.Percent{Value: b.cfg.Options.TracingSampleRate * 100},
			Provider:       tracingProvider,
		},
		// See https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_conn_man/headers#x-forwarded-for
		UseRemoteAddress:  &wrapperspb.BoolValue{Value: true},
		SkipXffAppend:     b.cfg.Options.SkipXffAppend,
		XffNumTrustedHops: b.cfg.Options.XffNumTrustedHops,
		LocalReplyConfig:  localReply,
		NormalizePath:     wrapperspb.Bool(true),
	}

	if fullyStatic {
		routeConfiguration, err := b.buildMainRouteConfiguration()
		if err != nil {
			return nil, err
		}
		mgr.RouteSpecifier = &envoy_http_connection_manager.HttpConnectionManager_RouteConfig{
			RouteConfig: routeConfiguration,
		}
	} else {
		mgr.RouteSpecifier = &envoy_http_connection_manager.HttpConnectionManager_Rds{
			Rds: &envoy_http_connection_manager.Rds{
				ConfigSource: &envoy_config_core_v3.ConfigSource{
					ResourceApiVersion:    envoy_config_core_v3.ApiVersion_V3,
					ConfigSourceSpecifier: &envoy_config_core_v3.ConfigSource_Ads{},
				},
				RouteConfigName: "main",
			},
		}
	}

	return HTTPConnectionManagerFilter(mgr), nil
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

func (b *Builder) buildGRPCListener(ctx context.Context) (*envoy_config_listener_v3.Listener, error) {
	filter, err := b.buildGRPCHTTPConnectionManagerFilter()
	if err != nil {
		return nil, err
	}

	filterChain := envoy_config_listener_v3.FilterChain{
		Filters: []*envoy_config_listener_v3.Filter{filter},
	}

	li := newEnvoyListener("grpc-ingress")
	li.FilterChains = []*envoy_config_listener_v3.FilterChain{&filterChain}

	if b.cfg.Options.GetGRPCInsecure() {
		li.Address = buildAddress(b.cfg.Options.GetGRPCAddr(), 80)
		return li, nil
	}

	li.Address = buildAddress(b.cfg.Options.GetGRPCAddr(), 443)
	li.ListenerFilters = []*envoy_config_listener_v3.ListenerFilter{
		TLSInspectorFilter(),
	}

	allCertificates, err := getAllCertificates(b.cfg)
	if err != nil {
		return nil, err
	}
	envoyCerts, err := b.envoyCertificates(ctx, allCertificates)
	if err != nil {
		return nil, err
	}
	tlsContext := &envoy_extensions_transport_sockets_tls_v3.DownstreamTlsContext{
		CommonTlsContext: &envoy_extensions_transport_sockets_tls_v3.CommonTlsContext{
			TlsParams:       tlsDownstreamParams,
			TlsCertificates: envoyCerts,
			AlpnProtocols:   []string{"h2"}, // gRPC requires HTTP/2
		},
	}
	filterChain.TransportSocket = &envoy_config_core_v3.TransportSocket{
		Name: "tls",
		ConfigType: &envoy_config_core_v3.TransportSocket_TypedConfig{
			TypedConfig: marshalAny(tlsContext),
		},
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

func (b *Builder) envoyCertificates(ctx context.Context, certs []tls.Certificate) (
	[]*envoy_extensions_transport_sockets_tls_v3.TlsCertificate, error,
) {
	envoyCerts := make([]*envoy_extensions_transport_sockets_tls_v3.TlsCertificate, 0, len(certs))
	for i := range certs {
		cert := &certs[i]
		if err := validateCertificate(cert); err != nil {
			return nil, fmt.Errorf("invalid certificate for domain %s: %w",
				cert.Leaf.Subject.CommonName, err)
		}
		envoyCert := b.envoyTLSCertificateFromGoTLSCertificate(ctx, cert)
		envoyCerts = append(envoyCerts, envoyCert)
	}
	return envoyCerts, nil
}

func (b *Builder) buildDownstreamTLSContextMulti(
	ctx context.Context,
	certs []tls.Certificate,
) (
	*envoy_extensions_transport_sockets_tls_v3.DownstreamTlsContext,
	error,
) {
	envoyCerts, err := b.envoyCertificates(ctx, certs)
	if err != nil {
		return nil, err
	}
	dtc := &envoy_extensions_transport_sockets_tls_v3.DownstreamTlsContext{
		CommonTlsContext: &envoy_extensions_transport_sockets_tls_v3.CommonTlsContext{
			TlsParams:       tlsDownstreamParams,
			TlsCertificates: envoyCerts,
			AlpnProtocols:   getALPNProtos(b.cfg.Options),
		},
	}
	b.buildDownstreamValidationContext(ctx, dtc)
	return dtc, nil
}

func getALPNProtos(opts *config.Options) []string {
	switch opts.GetCodecType() {
	case config.CodecTypeHTTP1:
		return []string{"http/1.1"}
	case config.CodecTypeHTTP2:
		return []string{"h2"}
	default:
		return []string{"h2", "http/1.1"}
	}
}

func (b *Builder) buildDownstreamValidationContext(
	ctx context.Context,
	dtc *envoy_extensions_transport_sockets_tls_v3.DownstreamTlsContext,
) {
	clientCA := clientCABundle(ctx, b.cfg)
	if len(clientCA) == 0 {
		return
	}

	vc := &envoy_extensions_transport_sockets_tls_v3.CertificateValidationContext{
		TrustedCa: b.opts.FileManager.BytesDataSource("client-ca.pem", clientCA),
		MatchTypedSubjectAltNames: make([]*envoy_extensions_transport_sockets_tls_v3.SubjectAltNameMatcher,
			0, len(b.cfg.Options.DownstreamMTLS.MatchSubjectAltNames)),
		OnlyVerifyLeafCertCrl: true,
	}
	for i := range b.cfg.Options.DownstreamMTLS.MatchSubjectAltNames {
		vc.MatchTypedSubjectAltNames = append(vc.MatchTypedSubjectAltNames,
			b.cfg.Options.DownstreamMTLS.MatchSubjectAltNames[i].ToEnvoyProto())
	}

	if d := b.cfg.Options.DownstreamMTLS.GetMaxVerifyDepth(); d > 0 {
		vc.MaxVerifyDepth = wrapperspb.UInt32(d)
	}

	if b.cfg.Options.DownstreamMTLS.GetEnforcement() == config.MTLSEnforcementRejectConnection {
		dtc.RequireClientCertificate = wrapperspb.Bool(true)
	} else {
		vc.TrustChainVerification = envoy_extensions_transport_sockets_tls_v3.CertificateValidationContext_ACCEPT_UNTRUSTED
	}

	if crl := b.cfg.Options.DownstreamMTLS.CRL; crl != "" {
		bs, err := base64.StdEncoding.DecodeString(crl)
		if err != nil {
			log.Ctx(ctx).Error().Err(err).Msg("invalid client CRL")
		} else {
			vc.Crl = b.opts.FileManager.BytesDataSource("client-crl.pem", bs)
		}
	} else if crlf := b.cfg.Options.DownstreamMTLS.CRLFile; crlf != "" {
		vc.Crl = b.opts.FileManager.FileDataSource(crlf)
	}

	dtc.CommonTlsContext.ValidationContextType = &envoy_extensions_transport_sockets_tls_v3.CommonTlsContext_ValidationContext{
		ValidationContext: vc,
	}
}

// clientCABundle returns a bundle of the globally configured client CA and any
// per-route client CAs.
func clientCABundle(ctx context.Context, cfg *config.Config) []byte {
	var bundle bytes.Buffer
	ca, _ := cfg.Options.DownstreamMTLS.GetCA()
	addCAToBundle(&bundle, ca)
	for p := range cfg.Options.GetAllPolicies() {
		// We don't need to check TLSDownstreamClientCAFile here because
		// Policy.Validate() will populate TLSDownstreamClientCA when
		// TLSDownstreamClientCAFile is set.
		if p.TLSDownstreamClientCA == "" {
			continue
		}
		ca, err := base64.StdEncoding.DecodeString(p.TLSDownstreamClientCA)
		if err != nil {
			log.Ctx(ctx).Error().Stringer("policy", p).Err(err).Msg("invalid client CA")
			continue
		}
		addCAToBundle(&bundle, ca)
	}
	return bundle.Bytes()
}

func addCAToBundle(bundle *bytes.Buffer, ca []byte) {
	if len(ca) == 0 {
		return
	}
	bundle.Write(ca)
	// Make sure each CA is separated by a newline.
	if ca[len(ca)-1] != '\n' {
		bundle.WriteByte('\n')
	}
}

func getAllRouteableHosts(options *config.Options, addr string) (*set.TreeSet[string], map[string][]config.IndexedPolicy, error) {
	allHosts := set.NewTreeSet(cmp.Compare[string])
	var policiesByHost map[string][]config.IndexedPolicy

	if addr == options.Addr {
		internalHosts, err := options.GetAllRouteableAuthenticateHTTPHosts()
		if err != nil {
			return nil, nil, err
		}
		policiesByHost, err = options.GetAllRouteablePolicyHTTPHosts()
		if err != nil {
			return nil, nil, err
		}
		allHosts.InsertSlice(internalHosts)
		for host := range policiesByHost {
			allHosts.Insert(host)
		}
	}

	if addr == options.GetGRPCAddr() {
		hosts, err := options.GetAllRouteableGRPCHosts()
		if err != nil {
			return nil, nil, err
		}
		allHosts.InsertSlice(hosts)
	}

	return allHosts, policiesByHost, nil
}

func (b *Builder) urlsMatchHost(urls []*url.URL, host string) bool {
	for _, u := range urls {
		if b.urlMatchesHost(u, host) {
			return true
		}
	}
	return false
}

func (b *Builder) urlMatchesHost(u *url.URL, host string) bool {
	if domains, ok := b.domainsForWellKnownURLs[u]; ok {
		for _, d := range domains {
			if d == host {
				return true
			}
		}
		return false
	}
	for _, h := range urlutil.GetDomainsForURL(u, true) {
		if h == host {
			return true
		}
	}
	return false
}

// newEnvoyListener creates envoy listener with certain default values
func newEnvoyListener(name string) *envoy_config_listener_v3.Listener {
	return &envoy_config_listener_v3.Listener{
		Name:                          name,
		PerConnectionBufferLimitBytes: wrapperspb.UInt32(listenerBufferLimit),

		// SO_REUSEPORT only works properly on linux and is force-disabled by
		// envoy on mac and windows, so we disable it explitly to avoid a
		// noisy log message
		EnableReusePort: wrapperspb.Bool(runtime.GOOS == "linux"),
	}
}

func shouldStartMainListener(options *config.Options) bool {
	return config.IsAuthenticate(options.Services) || config.IsProxy(options.Services)
}

func shouldStartGRPCListener(options *config.Options) bool {
	if options.GetGRPCAddr() == "" {
		return false
	}

	return config.IsAuthorize(options.Services) || config.IsDataBroker(options.Services)
}
