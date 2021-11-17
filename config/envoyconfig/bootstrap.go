package envoyconfig

import (
	"fmt"
	"os"

	envoy_config_accesslog_v3 "github.com/envoyproxy/go-control-plane/envoy/config/accesslog/v3"
	envoy_config_bootstrap_v3 "github.com/envoyproxy/go-control-plane/envoy/config/bootstrap/v3"
	envoy_config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_endpoint_v3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	envoy_config_metrics_v3 "github.com/envoyproxy/go-control-plane/envoy/config/metrics/v3"
	envoy_extensions_access_loggers_file_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/file/v3"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/telemetry"
)

// BuildBootstrapAdmin builds the admin config for the envoy bootstrap.
func (b *Builder) BuildBootstrapAdmin(cfg *config.Config) (admin *envoy_config_bootstrap_v3.Admin, err error) {
	admin = &envoy_config_bootstrap_v3.Admin{
		ProfilePath: cfg.Options.EnvoyAdminProfilePath,
	}

	admin.Address, err = parseAddress(cfg.Options.EnvoyAdminAddress)
	if err != nil {
		return nil, fmt.Errorf("envoyconfig: invalid envoy admin address: %w", err)
	}

	if cfg.Options.EnvoyAdminAccessLogPath != os.DevNull && cfg.Options.EnvoyAdminAccessLogPath != "" {
		tc := marshalAny(&envoy_extensions_access_loggers_file_v3.FileAccessLog{
			Path: cfg.Options.EnvoyAdminAccessLogPath,
		})
		admin.AccessLog = append(admin.AccessLog, &envoy_config_accesslog_v3.AccessLog{
			Name:       "envoy.access_loggers.file",
			ConfigType: &envoy_config_accesslog_v3.AccessLog_TypedConfig{TypedConfig: tc},
		})
	}

	return admin, nil
}

// BuildBootstrapClusterManager builds the bootstrap cluster manager.
func (b *Builder) BuildBootstrapClusterManager(cfg *config.Config) (*envoy_config_bootstrap_v3.ClusterManager, error) {
	mgr := &envoy_config_bootstrap_v3.ClusterManager{
		UpstreamBindConfig: &envoy_config_core_v3.BindConfig{
			SourceAddress: &envoy_config_core_v3.SocketAddress{
				Address: "0.0.0.0",
				PortSpecifier: &envoy_config_core_v3.SocketAddress_PortValue{
					PortValue: 0,
				},
			},
		},
	}

	if cfg.Options.EnvoyBindConfigFreebind.IsSet() {
		if mgr.UpstreamBindConfig == nil {
			mgr.UpstreamBindConfig = new(envoy_config_core_v3.BindConfig)
		}
		mgr.UpstreamBindConfig.Freebind = wrapperspb.Bool(cfg.Options.EnvoyBindConfigFreebind.Bool)
	}

	if cfg.Options.EnvoyBindConfigSourceAddress != "" {
		mgr.UpstreamBindConfig.SourceAddress.Address = cfg.Options.EnvoyBindConfigSourceAddress
	}

	return mgr, nil
}

// BuildBootstrapLayeredRuntime builds the layered runtime for the envoy bootstrap.
func (b *Builder) BuildBootstrapLayeredRuntime() (*envoy_config_bootstrap_v3.LayeredRuntime, error) {
	layer, err := structpb.NewStruct(map[string]interface{}{
		"overload": map[string]interface{}{
			"global_downstream_max_connections": 50000,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("envoyconfig: failed to create layered runtime layer: %w", err)
	}

	return &envoy_config_bootstrap_v3.LayeredRuntime{
		Layers: []*envoy_config_bootstrap_v3.RuntimeLayer{
			{
				Name: "static_layer_0",
				LayerSpecifier: &envoy_config_bootstrap_v3.RuntimeLayer_StaticLayer{
					StaticLayer: layer,
				},
			},
		},
	}, nil
}

// BuildBootstrapStaticResources builds the static resources for the envoy bootstrap. It includes the control plane
// cluster.
func (b *Builder) BuildBootstrapStaticResources() (*envoy_config_bootstrap_v3.Bootstrap_StaticResources, error) {
	grpcAddr, err := parseAddress(b.localGRPCAddress)
	if err != nil {
		return nil, fmt.Errorf("envoyconfig: invalid local gRPC address: %w", err)
	}

	controlPlaneEndpoint := &envoy_config_endpoint_v3.LbEndpoint_Endpoint{
		Endpoint: &envoy_config_endpoint_v3.Endpoint{
			Address: grpcAddr,
		},
	}

	controlPlaneCluster := &envoy_config_cluster_v3.Cluster{
		Name: "pomerium-control-plane-grpc",
		ConnectTimeout: &durationpb.Duration{
			Seconds: 5,
		},
		ClusterDiscoveryType: &envoy_config_cluster_v3.Cluster_Type{
			Type: envoy_config_cluster_v3.Cluster_STATIC,
		},
		LbPolicy: envoy_config_cluster_v3.Cluster_ROUND_ROBIN,
		LoadAssignment: &envoy_config_endpoint_v3.ClusterLoadAssignment{
			ClusterName: "pomerium-control-plane-grpc",
			Endpoints: []*envoy_config_endpoint_v3.LocalityLbEndpoints{
				{
					LbEndpoints: []*envoy_config_endpoint_v3.LbEndpoint{
						{
							HostIdentifier: controlPlaneEndpoint,
						},
					},
				},
			},
		},
		Http2ProtocolOptions: &envoy_config_core_v3.Http2ProtocolOptions{},
	}

	staticCfg := &envoy_config_bootstrap_v3.Bootstrap_StaticResources{
		Clusters: []*envoy_config_cluster_v3.Cluster{
			controlPlaneCluster,
		},
	}

	return staticCfg, nil
}

// BuildBootstrapStatsConfig builds a the stats config the envoy bootstrap.
func (b *Builder) BuildBootstrapStatsConfig(cfg *config.Config) (*envoy_config_metrics_v3.StatsConfig, error) {
	statsCfg := &envoy_config_metrics_v3.StatsConfig{}
	statsCfg.StatsTags = []*envoy_config_metrics_v3.TagSpecifier{{
		TagName: "service",
		TagValue: &envoy_config_metrics_v3.TagSpecifier_FixedValue{
			FixedValue: telemetry.ServiceName(cfg.Options.Services),
		},
	}}
	return statsCfg, nil
}
