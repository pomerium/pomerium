package envoyconfig

import (
	envoy_config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	set_filter_statev3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/common/set_filter_state/v3"
	envoy_extensions_filters_http_set_filter_state_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/set_filter_state/v3"
	envoy_extensions_filters_network_http_connection_manager "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	envoy_extensions_transport_sockets_internal_upstream_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/internal_upstream/v3"
	envoy_extensions_transport_sockets_raw_buffer_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/raw_buffer/v3"
	envoy_extensions_upstreams_http_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/upstreams/http/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"

	extensions_ssh "github.com/pomerium/envoy-custom/api/extensions/filters/network/ssh"
	extensions_event_sinks_grpc "github.com/pomerium/envoy-custom/api/extensions/health_check/event_sinks/grpc"
	"github.com/pomerium/pomerium/config"
)

func configureUpstreamTunnelCluster(policy *config.Policy, cluster *envoy_config_cluster_v3.Cluster) {
	cluster.UpstreamBindConfig = nil
	protocolOptions := cluster.TypedExtensionProtocolOptions["envoy.extensions.upstreams.http.v3.HttpProtocolOptions"]
	if protocolOptions == nil {
		panic("bug: invalid cluster config: expected HttpProtocolOptions to be set")
	}
	var httpOpts envoy_extensions_upstreams_http_v3.HttpProtocolOptions
	if err := protocolOptions.UnmarshalTo(&httpOpts); err != nil {
		panic(err)
	}
	if httpOpts.CommonHttpProtocolOptions == nil {
		httpOpts.CommonHttpProtocolOptions = &envoy_config_core_v3.HttpProtocolOptions{}
	}
	// This ensures that the upstream tunnel connections are not kept alive after
	// the downstream disconnects. Normally if the connection is left intact
	// (depending on the protocol) it can be kept alive to be reused later so as
	// to avoid the overhead of establishing a new connection. We could look into
	// configuring "pooled" tunneled connections, but it gets a bit complicated
	// since the pooling actually happens at the upstream openssh server, and the
	// connections are maintained by keeping the channel open. It is possible to
	// pool the channels for connection reuse, but needs more consideration first.
	httpOpts.CommonHttpProtocolOptions.MaxRequestsPerConnection = wrapperspb.UInt32(1)
	if err := protocolOptions.MarshalFrom(&httpOpts); err != nil {
		panic(err)
	}

	if cluster.TransportSocket == nil {
		if len(cluster.TransportSocketMatches) != 0 {
			panic("bug: invalid cluster config: TransportSocketMatches should be empty")
		}
		cluster.TransportSocket = &envoy_config_core_v3.TransportSocket{
			Name: "envoy.transport_sockets.raw_buffer",
			ConfigType: &envoy_config_core_v3.TransportSocket_TypedConfig{
				TypedConfig: marshalAny(&envoy_extensions_transport_sockets_raw_buffer_v3.RawBuffer{}),
			},
		}
		wrapTransportSocket(cluster.TransportSocket)
	} else {
		for i, match := range cluster.TransportSocketMatches {
			wrapTransportSocket(match.TransportSocket)
			if i == 0 {
				// We currently always set cluster.TransportSocket to the first entry in
				// TransportSocketMatches (they should point to the same object)
				if match.TransportSocket != cluster.TransportSocket {
					panic("bug: invalid cluster config: TransportSocket not set")
				}
			}
		}
	}

	grpcService := &envoy_config_core_v3.GrpcService{
		TargetSpecifier: &envoy_config_core_v3.GrpcService_EnvoyGrpc_{
			EnvoyGrpc: &envoy_config_core_v3.GrpcService_EnvoyGrpc{
				ClusterName: "pomerium-control-plane-grpc",
			},
		},
	}

	cluster.ClusterDiscoveryType = &envoy_config_cluster_v3.Cluster_ClusterType{
		ClusterType: &envoy_config_cluster_v3.Cluster_CustomClusterType{
			Name: "envoy.clusters.ssh_reverse_tunnel",
			TypedConfig: marshalAny(&extensions_ssh.ReverseTunnelCluster{
				Name: policy.MustRouteID(),
				EdsConfig: &envoy_config_core_v3.ConfigSource{
					ResourceApiVersion: envoy_config_core_v3.ApiVersion_V3,
					ConfigSourceSpecifier: &envoy_config_core_v3.ConfigSource_ApiConfigSource{
						ApiConfigSource: &envoy_config_core_v3.ApiConfigSource{
							ApiType:             envoy_config_core_v3.ApiConfigSource_DELTA_GRPC,
							TransportApiVersion: envoy_config_core_v3.ApiVersion_V3,
							GrpcServices: []*envoy_config_core_v3.GrpcService{
								grpcService,
							},
						},
					},
				},
			}),
		},
	}
	for _, hc := range cluster.HealthChecks {
		hc.ReuseConnection = wrapperspb.Bool(false)
		hc.EventLogger = append(hc.EventLogger, &envoy_config_core_v3.TypedExtensionConfig{
			Name: "envoy.health_check.event_sinks.grpc",
			TypedConfig: marshalAny(&extensions_event_sinks_grpc.Config{
				GrpcService: grpcService,
			}),
		})
	}
	// cluster.HealthChecks = []*envoy_config_core_v3.HealthCheck{
	// 	{
	// 		HealthChecker: &envoy_config_core_v3.HealthCheck_TcpHealthCheck_{
	// 			TcpHealthCheck: &envoy_config_core_v3.HealthCheck_TcpHealthCheck{},
	// 		},
	// 		EventLogger:},
	// 		},
	// 		Timeout:                      durationpb.New(1 * time.Second),
	// 		UnhealthyThreshold:           wrapperspb.UInt32(1),
	// 		HealthyThreshold:             wrapperspb.UInt32(1),
	// 		ReuseConnection:              wrapperspb.Bool(false),
	// 		AlwaysLogHealthCheckSuccess:  true,
	// 		AlwaysLogHealthCheckFailures: true,
	// 		Interval:                     durationpb.New(10 * time.Second),
	// 		InitialJitter:                durationpb.New(500 * time.Millisecond),
	// 		HealthyEdgeInterval:          durationpb.New(100 * time.Millisecond),
	// 		IntervalJitter:               durationpb.New(500 * time.Millisecond),
	// 		NoTrafficInterval:            durationpb.New(10 * time.Second),
	// 	},
	// }
}

func wrapTransportSocket(socket *envoy_config_core_v3.TransportSocket) {
	wrappedTypedConfig := &envoy_config_core_v3.TransportSocket_TypedConfig{
		TypedConfig: marshalAny(&envoy_extensions_transport_sockets_internal_upstream_v3.InternalUpstreamTransport{
			TransportSocket: proto.Clone(socket).(*envoy_config_core_v3.TransportSocket),
		}),
	}
	socket.Name = "envoy.transport_sockets.internal_upstream"
	socket.ConfigType = wrappedTypedConfig
}

func SetConnectionStateFilter() *envoy_extensions_filters_network_http_connection_manager.HttpFilter {
	// TODO: this would probably be better implemented via http PerFilterConfig
	return &envoy_extensions_filters_network_http_connection_manager.HttpFilter{
		Name: "envoy.filters.http.set_filter_state",
		ConfigType: &envoy_extensions_filters_network_http_connection_manager.HttpFilter_TypedConfig{
			TypedConfig: marshalAny(&envoy_extensions_filters_http_set_filter_state_v3.Config{
				OnRequestHeaders: []*set_filter_statev3.FilterStateValue{
					{
						Key: &set_filter_statev3.FilterStateValue_ObjectKey{
							ObjectKey: "pomerium.extensions.ssh.downstream_source_address",
						},
						Value: &set_filter_statev3.FilterStateValue_FormatString{
							FormatString: &envoy_config_core_v3.SubstitutionFormatString{
								Format: &envoy_config_core_v3.SubstitutionFormatString_TextFormatSource{
									TextFormatSource: &envoy_config_core_v3.DataSource{
										Specifier: &envoy_config_core_v3.DataSource_InlineString{
											InlineString: "%DOWNSTREAM_REMOTE_ADDRESS%",
										},
									},
								},
							},
						},
						SharedWithUpstream: set_filter_statev3.FilterStateValue_ONCE,
					},
					{
						Key: &set_filter_statev3.FilterStateValue_ObjectKey{
							ObjectKey: "pomerium.extensions.ssh.requested_server_name",
						},
						Value: &set_filter_statev3.FilterStateValue_FormatString{
							FormatString: &envoy_config_core_v3.SubstitutionFormatString{
								Format: &envoy_config_core_v3.SubstitutionFormatString_TextFormatSource{
									TextFormatSource: &envoy_config_core_v3.DataSource{
										Specifier: &envoy_config_core_v3.DataSource_InlineString{
											InlineString: "%REQUESTED_SERVER_NAME%",
										},
									},
								},
							},
						},
						SharedWithUpstream: set_filter_statev3.FilterStateValue_ONCE,
					},
					{
						Key: &set_filter_statev3.FilterStateValue_ObjectKey{
							ObjectKey: "pomerium.extensions.ssh.requested_path",
						},
						Value: &set_filter_statev3.FilterStateValue_FormatString{
							FormatString: &envoy_config_core_v3.SubstitutionFormatString{
								Format: &envoy_config_core_v3.SubstitutionFormatString_TextFormatSource{
									TextFormatSource: &envoy_config_core_v3.DataSource{
										Specifier: &envoy_config_core_v3.DataSource_InlineString{
											InlineString: "%PATH(NQ)%",
										},
									},
								},
							},
						},
						SharedWithUpstream: set_filter_statev3.FilterStateValue_ONCE,
					},
				},
			}),
		},
	}
}
