package controlplane

import (
	"errors"
	"time"

	envoy_config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	"github.com/golang/protobuf/ptypes"
)

var (
	noLbWeight uint32 = 0
)

var (
	errNoEndpoints           = errors.New("cluster must have endpoints")
	defaultConnectionTimeout = ptypes.DurationProto(time.Second * 10)
)

// newDefaultEnvoyClusterConfig creates envoy cluster with certain default values
func newDefaultEnvoyClusterConfig() *envoy_config_cluster_v3.Cluster {
	return &envoy_config_cluster_v3.Cluster{
		ConnectTimeout:  defaultConnectionTimeout,
		RespectDnsTtl:   true,
		DnsLookupFamily: envoy_config_cluster_v3.Cluster_AUTO,
	}
}
