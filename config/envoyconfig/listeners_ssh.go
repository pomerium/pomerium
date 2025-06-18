package envoyconfig

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"time"

	xds_core_v3 "github.com/cncf/xds/go/xds/core/v3"
	xds_matcher_v3 "github.com/cncf/xds/go/xds/type/matcher/v3"
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_listener_v3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_generic_proxy_action_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/generic_proxy/action/v3"
	envoy_generic_proxy_matcher_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/generic_proxy/matcher/v3"
	envoy_generic_router_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/generic_proxy/router/v3"
	envoy_generic_proxy_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/generic_proxy/v3"
	matcherv3 "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	extensions_ssh "github.com/pomerium/envoy-custom/api/extensions/filters/network/ssh"
	"github.com/pomerium/pomerium/config"
	"google.golang.org/protobuf/types/known/durationpb"
)

func fileDataSource(filename string) *envoy_config_core_v3.DataSource {
	return &envoy_config_core_v3.DataSource{
		Specifier: &envoy_config_core_v3.DataSource_Filename{
			Filename: filename,
		},
	}
}

func (b *Builder) buildSSHListener(ctx context.Context, cfg *config.Config) (*envoy_config_listener_v3.Listener, error) {
	rc, err := b.buildRouteConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	var grpcClientTimeout *durationpb.Duration
	if cfg.Options.GRPCClientTimeout != 0 {
		grpcClientTimeout = durationpb.New(cfg.Options.GRPCClientTimeout)
	} else {
		grpcClientTimeout = durationpb.New(30 * time.Second)
	}
	os.MkdirAll("/tmp/recordings", 0o755)
	authorizeService := &envoy_config_core_v3.GrpcService{
		Timeout: grpcClientTimeout,
		TargetSpecifier: &envoy_config_core_v3.GrpcService_EnvoyGrpc_{
			EnvoyGrpc: &envoy_config_core_v3.GrpcService_EnvoyGrpc{
				ClusterName: "pomerium-authorize",
			},
		},
	}
	li := &envoy_config_listener_v3.Listener{
		Name:    "ssh",
		Address: buildTCPAddress(cfg.Options.SSHAddr, 22),
		FilterChains: []*envoy_config_listener_v3.FilterChain{
			{
				Filters: []*envoy_config_listener_v3.Filter{
					{
						Name: "generic_proxy",
						ConfigType: &envoy_config_listener_v3.Filter_TypedConfig{
							TypedConfig: marshalAny(&envoy_generic_proxy_v3.GenericProxy{
								StatPrefix: "ssh",
								CodecConfig: &envoy_config_core_v3.TypedExtensionConfig{
									Name: "envoy.generic_proxy.codecs.ssh",
									TypedConfig: marshalAny(&extensions_ssh.CodecConfig{
										HostKeys: []*envoy_config_core_v3.DataSource{
											fileDataSource(cfg.Options.SSHHostKeys[0]),
										},
										UserCaKey:   fileDataSource(cfg.Options.SSHUserCAKey),
										GrpcService: authorizeService,
									}),
								},
								Filters: []*envoy_config_core_v3.TypedExtensionConfig{
									// {
									// 	Name: "envoy.filters.generic.ssh.session_recording",
									// 	TypedConfig: marshalAny(&extensions_ssh_session_recording.Config{
									// 		StorageDir:  "/tmp/recordings",
									// 		GrpcService: authorizeService,
									// 		CompressorLibrary: &envoy_config_core_v3.TypedExtensionConfig{
									// 			Name: "envoy.compression.zstd.compressor",
									// 			TypedConfig: marshalAny(&extensions_compressor_zstd_v3.Zstd{
									// 				CompressionLevel: wrapperspb.UInt32(19),
									// 				EnableChecksum:   false,
									// 				Strategy:         extensions_compressor_zstd_v3.Zstd_BTULTRA2,
									// 				ChunkSize:        wrapperspb.UInt32(8192),
									// 			}),
									// 		},
									// 		// FileManagerConfig: &async_filesv3.AsyncFileManagerConfig{
									// 		// 	ManagerType: &async_filesv3.AsyncFileManagerConfig_ThreadPool_{
									// 		// 		ThreadPool: &async_filesv3.AsyncFileManagerConfig_ThreadPool{
									// 		// 			ThreadCount: 2,
									// 		// 		},
									// 		// 	},
									// 		// },
									// 	}),
									// },
									// {
									// 	Name:        "envoy.filters.generic.ssh.session_multiplexing",
									// 	TypedConfig: marshalAny(&extensions_ssh_session_multiplexing.Config{}),
									// },
									{
										Name: "envoy.filters.generic.router",
										TypedConfig: marshalAny(&envoy_generic_router_v3.Router{
											BindUpstreamConnection: true,
										}),
									},
								},
								RouteSpecifier: &envoy_generic_proxy_v3.GenericProxy_RouteConfig{
									RouteConfig: rc,
								},
							}),
						},
					},
				},
			},
		},
	}
	return li, nil
}

func (b *Builder) buildRouteConfig(_ context.Context, cfg *config.Config) (*envoy_generic_proxy_v3.RouteConfiguration, error) {
	routeMatchers := []*xds_matcher_v3.Matcher_MatcherList_FieldMatcher{}
	for route := range cfg.Options.GetAllPolicies() {
		from, err := url.Parse(route.From)
		if err != nil {
			return nil, err
		}
		if from.Scheme != "ssh" {
			continue
		}
		fromHost := from.Hostname()
		if len(route.To) > 1 {
			return nil, fmt.Errorf("only one 'to' entry allowed for ssh routes")
		}
		to := route.To[0].URL
		if to.Scheme != "ssh" {
			return nil, fmt.Errorf("'to' route url must have ssh scheme")
		}
		clusterId := getClusterID(route)
		routeMatchers = append(routeMatchers, &xds_matcher_v3.Matcher_MatcherList_FieldMatcher{
			Predicate: &xds_matcher_v3.Matcher_MatcherList_Predicate{
				MatchType: &xds_matcher_v3.Matcher_MatcherList_Predicate_SinglePredicate_{
					SinglePredicate: &xds_matcher_v3.Matcher_MatcherList_Predicate_SinglePredicate{
						Input: &xds_core_v3.TypedExtensionConfig{
							Name:        "request",
							TypedConfig: marshalAny(&envoy_generic_proxy_matcher_v3.RequestMatchInput{}),
						},
						Matcher: &xds_matcher_v3.Matcher_MatcherList_Predicate_SinglePredicate_CustomMatch{
							CustomMatch: &xds_core_v3.TypedExtensionConfig{
								Name: "request",
								TypedConfig: marshalAny(&envoy_generic_proxy_matcher_v3.RequestMatcher{
									Host: &matcherv3.StringMatcher{
										MatchPattern: &matcherv3.StringMatcher_Exact{
											Exact: fromHost,
										},
									},
								}),
							},
						},
					},
				},
			},
			OnMatch: &xds_matcher_v3.Matcher_OnMatch{
				OnMatch: &xds_matcher_v3.Matcher_OnMatch_Action{
					Action: &xds_core_v3.TypedExtensionConfig{
						Name: "route",
						TypedConfig: marshalAny(&envoy_generic_proxy_action_v3.RouteAction{
							Name: route.ID,
							ClusterSpecifier: &envoy_generic_proxy_action_v3.RouteAction_Cluster{
								Cluster: clusterId,
							},
							Timeout: durationpb.New(0),
						}),
					},
				},
			},
		})
	}
	return &envoy_generic_proxy_v3.RouteConfiguration{
		Name: "route_config",
		VirtualHosts: []*envoy_generic_proxy_v3.VirtualHost{
			{
				Name:  "ssh",
				Hosts: []string{"*"},
				Routes: &xds_matcher_v3.Matcher{
					MatcherType: &xds_matcher_v3.Matcher_MatcherList_{
						MatcherList: &xds_matcher_v3.Matcher_MatcherList{
							Matchers: routeMatchers,
						},
					},
				},
			},
		},
	}, nil
}
