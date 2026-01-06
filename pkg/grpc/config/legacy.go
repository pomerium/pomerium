package config

import (
	envoy_config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"

	"github.com/pomerium/pomerium/pkg/protoutil"
)

// SetEnvoyOpts sets the envoy options field for a route. This field was removed from the
// current protobuf definition, but it used to exist as tag 36 and can be sent as an unknown
// field for older versions of Pomerium.
func (x *Route) SetEnvoyOpts(cluster *envoy_config_cluster_v3.Cluster) error {
	return protoutil.MarshalUnknownField(x, 36, cluster)
}
