package envoyconfig

import (
	"strings"

	xds_type_v3 "github.com/cncf/xds/go/xds/type/v3"
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_listener_v3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_config_ratelimit_v3 "github.com/envoyproxy/go-control-plane/envoy/config/ratelimit/v3"
	envoy_common_ratelimit_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/common/ratelimit/v3"
	envoy_generic_router_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/generic_proxy/router/v3"
	envoy_generic_proxy_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/generic_proxy/v3"
	envoy_generic_ratelimit_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/ratelimit/v3"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	extensions_ssh "github.com/pomerium/envoy-custom/api/extensions/filters/network/ssh"
	xssh "github.com/pomerium/envoy-custom/api/x/recording/formats/ssh"
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

func buildSSHListener(cfg *config.Config, extensionsToLoad []string) (*envoy_config_listener_v3.Listener, error) {
	if cfg.Options.SSHAddr == "" {
		return nil, nil
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
		additionalEntries := slices.Map(cfg.Options.SSHRLSAdditonalEntries, func(el config.GenericKeyVal) *envoy_common_ratelimit_v3.RateLimitDescriptor_Entry {
			return &envoy_common_ratelimit_v3.RateLimitDescriptor_Entry{
				Key:   el.Key,
				Value: el.Value,
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

	var enabledChannelFilters []*envoy_config_core_v3.TypedExtensionConfig
	if slices.Contains(extensionsToLoad, ExtensionSSHSessionRecording) {
		ext := &xssh.ChannelFilterConfig{}
		ts := &xds_type_v3.TypedStruct{
			TypeUrl: "type.googleapis.com/" + string(ext.ProtoReflect().Descriptor().FullName()),
			Value:   &structpb.Struct{},
		}
		data, err := protojson.Marshal(ext)
		if err != nil {
			return nil, err
		}
		if err := protojson.Unmarshal(data, ts.Value); err != nil {
			return nil, err
		}
		enabledChannelFilters = append(enabledChannelFilters, &envoy_config_core_v3.TypedExtensionConfig{
			Name:        "session_recording",
			TypedConfig: marshalAny(ts),
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
							HostKeys:                      hostKeyDataSources,
							UserCaKey:                     userCaKeyDataSource,
							GrpcService:                   authorizeService,
							EnabledChannelFilterFactories: enabledChannelFilters,
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
					RouteSpecifier: &envoy_generic_proxy_v3.GenericProxy_GenericRds{
						GenericRds: &envoy_generic_proxy_v3.GenericRds{
							ConfigSource: &envoy_config_core_v3.ConfigSource{
								ResourceApiVersion:    envoy_config_core_v3.ApiVersion_V3,
								ConfigSourceSpecifier: &envoy_config_core_v3.ConfigSource_Ads{},
							},
							// Matches the ssh generic proxy RouteConfiguration created by
							// buildSSHRouteConfiguration in route_configurations.go.
							RouteConfigName: "ssh",
						},
					},
				}),
			},
		},
	)

	li := &envoy_config_listener_v3.Listener{
		Name: "ssh",
		FilterChains: []*envoy_config_listener_v3.FilterChain{
			{
				Filters: filters,
			},
		},
		PerConnectionBufferLimitBytes: wrapperspb.UInt32(sshConnectionBufferLimit),
	}
	li.Address, li.AdditionalAddresses = buildTCPListenAddresses(cfg.Options.SSHAddr, 22)
	return li, nil
}

func shouldStartSSHListener(options *config.Options) bool {
	return config.IsProxy(options.Services)
}
