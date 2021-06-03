package envoyconfig

import (
	"fmt"

	envoy_config_bootstrap_v3 "github.com/envoyproxy/go-control-plane/envoy/config/bootstrap/v3"
	envoy_config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_endpoint_v3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	envoy_config_metrics_v3 "github.com/envoyproxy/go-control-plane/envoy/config/metrics/v3"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/telemetry"
)

// BuildBootstrapAdmin builds the admin config for the envoy bootstrap.
func (b *Builder) BuildBootstrapAdmin(cfg *config.Config) (*envoy_config_bootstrap_v3.Admin, error) {
	adminAddr, err := parseAddress(cfg.Options.EnvoyAdminAddress)
	if err != nil {
		return nil, fmt.Errorf("envoyconfig: invalid envoy admin address: %w", err)
	}
	return &envoy_config_bootstrap_v3.Admin{
		AccessLogPath: cfg.Options.EnvoyAdminAccessLogPath,
		ProfilePath:   cfg.Options.EnvoyAdminProfilePath,
		Address:       adminAddr,
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
