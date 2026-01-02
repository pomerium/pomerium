package config

import (
	envoy_config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"google.golang.org/protobuf/proto"
)

func (x *HealthCheck) ToEnvoy() *envoy_config_core_v3.HealthCheck {
	return protoToProto[envoy_config_core_v3.HealthCheck](x)
}

func (x *OutlierDetection) ToEnvoy() *envoy_config_cluster_v3.OutlierDetection {
	return protoToProto[envoy_config_cluster_v3.OutlierDetection](x)
}

func (x *LoadBalancingPolicy) ToEnvoy() envoy_config_cluster_v3.Cluster_LbPolicy {
	if x == nil {
		return 0
	}
	switch *x {
	case LoadBalancingPolicy_LOAD_BALANCING_POLICY_MAGLEV:
		return envoy_config_cluster_v3.Cluster_MAGLEV
	case LoadBalancingPolicy_LOAD_BALANCING_POLICY_RANDOM:
		return envoy_config_cluster_v3.Cluster_RANDOM
	case LoadBalancingPolicy_LOAD_BALANCING_POLICY_RING_HASH:
		return envoy_config_cluster_v3.Cluster_RING_HASH
	case LoadBalancingPolicy_LOAD_BALANCING_POLICY_LEAST_REQUEST:
		return envoy_config_cluster_v3.Cluster_LEAST_REQUEST
	default:
		return envoy_config_cluster_v3.Cluster_ROUND_ROBIN
	}
}

func protoToProto[T any, TMsg interface {
	*T
	proto.Message
}](src proto.Message) TMsg {
	if src == nil {
		return nil
	}

	var dst T
	proto.Reset(TMsg(&dst))
	b, err := (&proto.MarshalOptions{AllowPartial: true}).Marshal(src)
	if err != nil {
		panic(err)
	}
	err = (&proto.UnmarshalOptions{
		AllowPartial: true,
	}).Unmarshal(b, TMsg(&dst))
	if err != nil {
		panic(err)
	}
	return TMsg(&dst)
}
