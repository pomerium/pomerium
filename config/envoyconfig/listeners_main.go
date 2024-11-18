package envoyconfig

import (
	"context"
	"time"

	envoy_config_accesslog_v3 "github.com/envoyproxy/go-control-plane/envoy/config/accesslog/v3"
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_listener_v3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_extensions_access_loggers_grpc_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/grpc/v3"
	envoy_extensions_filters_network_http_connection_manager "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	envoy_type_v3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/pomerium/pomerium/config"
)

func (b *Builder) buildMainListener(
	ctx context.Context,
	cfg *config.Config,
	fullyStatic bool,
) (*envoy_config_listener_v3.Listener, error) {
	if cfg.Options.InsecureServer {
		return b.buildMainInsecureListener(ctx, cfg, fullyStatic)
	}
	return b.buildMainTLSListener(ctx, cfg, fullyStatic)
}

func (b *Builder) buildMainInsecureListener(
	ctx context.Context,
	cfg *config.Config,
	fullyStatic bool,
) (*envoy_config_listener_v3.Listener, error) {
	li := newListener("http-ingress")
	li.Address = buildAddress(cfg.Options.Addr, 80)

	// listener filters
	if cfg.Options.UseProxyProtocol {
		li.ListenerFilters = append(li.ListenerFilters, ProxyProtocolFilter())
	}

	filterChain, err := b.buildMainHTTPConnectionManagerFilterChain(ctx, cfg, fullyStatic, nil)
	if err != nil {
		return nil, err
	}
	li.FilterChains = append(li.FilterChains, filterChain)

	return li, nil
}

func (b *Builder) buildMainTLSListener(
	ctx context.Context,
	cfg *config.Config,
	fullyStatic bool,
) (*envoy_config_listener_v3.Listener, error) {
	li := newListener("https-ingress")
	li.Address = buildAddress(cfg.Options.Addr, 443)

	// listener filters
	if cfg.Options.UseProxyProtocol {
		li.ListenerFilters = append(li.ListenerFilters, ProxyProtocolFilter())
	}
	li.ListenerFilters = append(li.ListenerFilters, TLSInspectorFilter())

	// access log
	if cfg.Options.DownstreamMTLS.Enforcement == config.MTLSEnforcementRejectConnection {
		li.AccessLog = append(li.AccessLog, newListenerAccessLog())
	}

	// filter chains
	li.FilterChains = append(li.FilterChains, b.buildACMETLSALPNFilterChain())

	allCertificates, err := getAllCertificates(cfg)
	if err != nil {
		return nil, err
	}

	tlsContext, err := b.buildDownstreamTLSContextMulti(ctx, cfg, allCertificates)
	if err != nil {
		return nil, err
	}

	filterChain, err := b.buildMainHTTPConnectionManagerFilterChain(ctx, cfg, fullyStatic, newDownstreamTLSTransportSocket(tlsContext))
	if err != nil {
		return nil, err
	}
	li.FilterChains = append(li.FilterChains, filterChain)

	return li, nil
}

func (b *Builder) buildMainHTTPConnectionManagerFilterChain(
	ctx context.Context,
	cfg *config.Config,
	fullyStatic bool,
	transportSocket *envoy_config_core_v3.TransportSocket,
) (*envoy_config_listener_v3.FilterChain, error) {
	filter, err := b.buildMainHTTPConnectionManagerFilter(ctx, cfg, fullyStatic)
	if err != nil {
		return nil, err
	}
	return &envoy_config_listener_v3.FilterChain{
		Filters:         []*envoy_config_listener_v3.Filter{filter},
		TransportSocket: transportSocket,
	}, nil
}

func (b *Builder) buildMainHTTPConnectionManagerFilter(
	ctx context.Context,
	cfg *config.Config,
	fullyStatic bool,
) (*envoy_config_listener_v3.Filter, error) {
	var grpcClientTimeout *durationpb.Duration
	if cfg.Options.GRPCClientTimeout != 0 {
		grpcClientTimeout = durationpb.New(cfg.Options.GRPCClientTimeout)
	} else {
		grpcClientTimeout = durationpb.New(30 * time.Second)
	}

	filters := []*envoy_extensions_filters_network_http_connection_manager.HttpFilter{
		LuaFilter(luascripts.RemoveImpersonateHeaders),
		LuaFilter(luascripts.SetClientCertificateMetadata),
		ExtAuthzFilter(grpcClientTimeout),
		LuaFilter(luascripts.ExtAuthzSetCookie),
		LuaFilter(luascripts.CleanUpstream),
		LuaFilter(luascripts.RewriteHeaders),
	}
	filters = append(filters, HTTPRouterFilter())

	var maxStreamDuration *durationpb.Duration
	if cfg.Options.WriteTimeout > 0 {
		maxStreamDuration = durationpb.New(cfg.Options.WriteTimeout)
	}

	tracingProvider, err := buildTracingHTTP(cfg.Options)
	if err != nil {
		return nil, err
	}

	localReply, err := b.buildLocalReplyConfig(cfg.Options)
	if err != nil {
		return nil, err
	}

	mgr := &envoy_extensions_filters_network_http_connection_manager.HttpConnectionManager{
		AlwaysSetRequestIdInResponse: true,
		CodecType:                    cfg.Options.GetCodecType().ToEnvoy(),
		StatPrefix:                   "ingress",
		HttpFilters:                  filters,
		AccessLog:                    buildAccessLogs(cfg.Options),
		CommonHttpProtocolOptions: &envoy_config_core_v3.HttpProtocolOptions{
			IdleTimeout:       durationpb.New(cfg.Options.IdleTimeout),
			MaxStreamDuration: maxStreamDuration,
		},
		HttpProtocolOptions: http1ProtocolOptions,
		RequestTimeout:      durationpb.New(cfg.Options.ReadTimeout),
		Tracing: &envoy_extensions_filters_network_http_connection_manager.HttpConnectionManager_Tracing{
			RandomSampling: &envoy_type_v3.Percent{Value: cfg.Options.TracingSampleRate * 100},
			Provider:       tracingProvider,
		},
		// See https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_conn_man/headers#x-forwarded-for
		UseRemoteAddress:  &wrapperspb.BoolValue{Value: true},
		SkipXffAppend:     cfg.Options.SkipXffAppend,
		XffNumTrustedHops: cfg.Options.XffNumTrustedHops,
		LocalReplyConfig:  localReply,
		NormalizePath:     wrapperspb.Bool(true),
	}

	if fullyStatic {
		routeConfiguration, err := b.buildMainRouteConfiguration(ctx, cfg)
		if err != nil {
			return nil, err
		}
		mgr.RouteSpecifier = &envoy_extensions_filters_network_http_connection_manager.HttpConnectionManager_RouteConfig{
			RouteConfig: routeConfiguration,
		}
	} else {
		mgr.RouteSpecifier = &envoy_extensions_filters_network_http_connection_manager.HttpConnectionManager_Rds{
			Rds: &envoy_extensions_filters_network_http_connection_manager.Rds{
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

func newListenerAccessLog() *envoy_config_accesslog_v3.AccessLog {
	return &envoy_config_accesslog_v3.AccessLog{
		Name: "envoy.access_loggers.tcp_grpc",
		ConfigType: &envoy_config_accesslog_v3.AccessLog_TypedConfig{
			TypedConfig: marshalAny(&envoy_extensions_access_loggers_grpc_v3.TcpGrpcAccessLogConfig{
				CommonConfig: &envoy_extensions_access_loggers_grpc_v3.CommonGrpcAccessLogConfig{
					LogName: "ingress-http-listener",
					GrpcService: &envoy_config_core_v3.GrpcService{
						TargetSpecifier: &envoy_config_core_v3.GrpcService_EnvoyGrpc_{
							EnvoyGrpc: &envoy_config_core_v3.GrpcService_EnvoyGrpc{
								ClusterName: "pomerium-control-plane-grpc",
							},
						},
					},
					TransportApiVersion: envoy_config_core_v3.ApiVersion_V3,
				},
			}),
		},
	}
}

func shouldStartMainListener(options *config.Options) bool {
	return config.IsAuthenticate(options.Services) || config.IsProxy(options.Services)
}
