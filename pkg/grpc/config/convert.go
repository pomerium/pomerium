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
	return envoy_config_cluster_v3.Cluster_LbPolicy(*x)
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
		AllowPartial:   true,
		DiscardUnknown: true,
	}).Unmarshal(b, TMsg(&dst))
	if err != nil {
		panic(err)
	}
	return TMsg(&dst)
}
