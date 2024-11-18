package envoyconfig

import (
	"context"
	"os"
	"path/filepath"

	envoy_config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_endpoint_v3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"

	"github.com/pomerium/pomerium/config"
)

func (b *Builder) buildEnvoyAdminCluster(_ context.Context, _ *config.Config) (*envoy_config_cluster_v3.Cluster, error) {
	return &envoy_config_cluster_v3.Cluster{
		Name:           envoyAdminClusterName,
		ConnectTimeout: defaultConnectionTimeout,
		LoadAssignment: &envoy_config_endpoint_v3.ClusterLoadAssignment{
			ClusterName: envoyAdminClusterName,
			Endpoints: []*envoy_config_endpoint_v3.LocalityLbEndpoints{{
				LbEndpoints: []*envoy_config_endpoint_v3.LbEndpoint{{
					HostIdentifier: &envoy_config_endpoint_v3.LbEndpoint_Endpoint{
						Endpoint: &envoy_config_endpoint_v3.Endpoint{
							Address: &envoy_config_core_v3.Address{
								Address: &envoy_config_core_v3.Address_Pipe{
									Pipe: &envoy_config_core_v3.Pipe{
										Path: filepath.Join(os.TempDir(), envoyAdminAddressSockName),
										Mode: uint32(envoyAdminAddressMode),
									},
								},
							},
						},
					},
				}},
			}},
		},
	}, nil
}
