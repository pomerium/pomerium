package envoyconfig

import (
	"fmt"
	"net/url"
	"strings"

	xds_core_v3 "github.com/cncf/xds/go/xds/core/v3"
	xds_matcher_v3 "github.com/cncf/xds/go/xds/type/matcher/v3"
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_listener_v3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_config_ratelimit_v3 "github.com/envoyproxy/go-control-plane/envoy/config/ratelimit/v3"
	envoy_common_ratelimit_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/common/ratelimit/v3"
	envoy_generic_proxy_action_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/generic_proxy/action/v3"
	envoy_generic_proxy_matcher_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/generic_proxy/matcher/v3"
	envoy_generic_router_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/generic_proxy/router/v3"
	envoy_generic_proxy_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/generic_proxy/v3"
	envoy_generic_ratelimit_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/ratelimit/v3"
	matcherv3 "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"google.golang.org/protobuf/types/known/durationpb"

	extensions_ssh "github.com/pomerium/envoy-custom/api/extensions/filters/network/ssh"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/slices"
	"github.com/pomerium/pomerium/pkg/ssh/ratelimit"
)

func newRateLimitEntries() []*envoy_common_ratelimit_v3.RateLimitDescriptor_Entry {
	return []*envoy_common_ratelimit_v3.RateLimitDescriptor_Entry{
		{
			Key:   ratelimit.EntryDownstreamIP,
			Value: ratelimit.DownstreamDirectRemoteAddressWithoutPort,
		},
		{
			Key:   "connection_id",
			Value: "%CONNECTION_ID%",
		},
		{
			Key:   "unique_id",
			Value: "%UNIQUE_ID%",
		},
	}
}

func buildSSHListener(cfg *config.Config) (*envoy_config_listener_v3.Listener, error) {
	if cfg.Options.SSHAddr == "" {
		return nil, nil
	}
	rc, err := buildRouteConfig(cfg)
	if err != nil {
		return nil, err
	}

	authorizeService := &envoy_config_core_v3.GrpcService{
		Timeout: durationpb.New(0),
		TargetSpecifier: &envoy_config_core_v3.GrpcService_EnvoyGrpc_{
			EnvoyGrpc: &envoy_config_core_v3.GrpcService_EnvoyGrpc{
				ClusterName: "pomerium-authorize",
			},
		},
	}

	var hostKeyDataSources []*envoy_config_core_v3.DataSource
	if cfg.Options.SSHHostKeyFiles != nil {
		for _, filename := range *cfg.Options.SSHHostKeyFiles {
			hostKeyDataSources = append(hostKeyDataSources, &envoy_config_core_v3.DataSource{
				Specifier: &envoy_config_core_v3.DataSource_Filename{
					Filename: filename,
				},
			})
		}
	}
	if cfg.Options.SSHHostKeys != nil {
		for _, key := range *cfg.Options.SSHHostKeys {
			if !strings.HasSuffix(key, "\n") {
				key += "\n"
			}
			hostKeyDataSources = append(hostKeyDataSources, &envoy_config_core_v3.DataSource{
				Specifier: &envoy_config_core_v3.DataSource_InlineString{
					InlineString: key,
				},
			})
		}
	}
	var userCaKeyDataSource *envoy_config_core_v3.DataSource
	if cfg.Options.SSHUserCAKeyFile != "" {
		userCaKeyDataSource = &envoy_config_core_v3.DataSource{
			Specifier: &envoy_config_core_v3.DataSource_Filename{
				Filename: cfg.Options.SSHUserCAKeyFile,
			},
		}
	} else if cfg.Options.SSHUserCAKey != "" {
		key := cfg.Options.SSHUserCAKey
		if !strings.HasSuffix(key, "\n") {
			key += "\n"
		}
		userCaKeyDataSource = &envoy_config_core_v3.DataSource{
			Specifier: &envoy_config_core_v3.DataSource_InlineString{
				InlineString: key,
			},
		}
	}

	filters := []*envoy_config_listener_v3.Filter{}

	if cfg.Options.SSHRLSEnabled {
		additionalEntries := slices.Map(cfg.Options.SSHRLSAdditonalEntries, func(el [2]string) *envoy_common_ratelimit_v3.RateLimitDescriptor_Entry {
			return &envoy_common_ratelimit_v3.RateLimitDescriptor_Entry{
				Key:   el[0],
				Value: el[1],
			}
		})

		rl := &envoy_generic_ratelimit_v3.RateLimit{
			StatPrefix: "ratelimit",
			Domain:     ratelimit.DomainSSHInbound,
			Descriptors: []*envoy_common_ratelimit_v3.RateLimitDescriptor{
				{
					Entries: append(newRateLimitEntries(), additionalEntries...),
				},
			},
			RateLimitService: &envoy_config_ratelimit_v3.RateLimitServiceConfig{
				TransportApiVersion: envoy_config_core_v3.ApiVersion_V3,
				GrpcService: &envoy_config_core_v3.GrpcService{
					TargetSpecifier: &envoy_config_core_v3.GrpcService_EnvoyGrpc_{
						EnvoyGrpc: &envoy_config_core_v3.GrpcService_EnvoyGrpc{
							ClusterName: "pomerium-control-plane-grpc",
						},
					},
				},
			},
		}
		rlsCfg := marshalAny(rl)
		filters = append(filters, &envoy_config_listener_v3.Filter{
			Name: "ssh-inbound-ratelimit",
			ConfigType: &envoy_config_listener_v3.Filter_TypedConfig{
				TypedConfig: rlsCfg,
			},
		})
	}

	filters = append(
		filters, &envoy_config_listener_v3.Filter{
			Name: "generic_proxy",
			ConfigType: &envoy_config_listener_v3.Filter_TypedConfig{
				TypedConfig: marshalAny(&envoy_generic_proxy_v3.GenericProxy{
					StatPrefix: "ssh",
					CodecConfig: &envoy_config_core_v3.TypedExtensionConfig{
						Name: "envoy.generic_proxy.codecs.ssh",
						TypedConfig: marshalAny(&extensions_ssh.CodecConfig{
							HostKeys:    hostKeyDataSources,
							UserCaKey:   userCaKeyDataSource,
							GrpcService: authorizeService,
						}),
					},
					Filters: []*envoy_config_core_v3.TypedExtensionConfig{
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
	)

	li := &envoy_config_listener_v3.Listener{
		Name:    "ssh",
		Address: buildTCPAddress(cfg.Options.SSHAddr, 22),
		FilterChains: []*envoy_config_listener_v3.FilterChain{
			{
				Filters: filters,
			},
		},
	}
	return li, nil
}

func buildRouteConfig(cfg *config.Config) (*envoy_generic_proxy_v3.RouteConfiguration, error) {
	var routeMatchers []*xds_matcher_v3.Matcher_MatcherList_FieldMatcher
	for route := range cfg.Options.GetAllPolicies() {
		if !route.IsSSH() {
			continue
		}
		from, err := url.Parse(route.From)
		if err != nil {
			return nil, err
		}
		fromHost := from.Hostname()
		if len(route.To) > 1 {
			return nil, fmt.Errorf("only one 'to' entry allowed for ssh routes")
		}
		to := route.To[0].URL
		if to.Scheme != "ssh" {
			return nil, fmt.Errorf("'to' route url must have ssh scheme")
		}
		clusterID := GetClusterID(route)
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
								Cluster: clusterID,
							},
							Timeout: durationpb.New(0),
						}),
					},
				},
			},
		})
	}
	if len(routeMatchers) == 0 {
		return &envoy_generic_proxy_v3.RouteConfiguration{
			Name: "route_config",
		}, nil
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

func shouldStartSSHListener(options *config.Options) bool {
	return config.IsProxy(options.Services)
}
