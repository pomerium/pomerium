package envoyconfig

import (
	"math"

	envoy_config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/pomerium/pomerium/config"
)

// unlimitedCircuitBreakersThreshold sets the circuit breaking thresholds to the maximum value, effectively disabling them
var unlimitedCircuitBreakersThreshold = &envoy_config_cluster_v3.CircuitBreakers_Thresholds{
	Priority:           envoy_config_core_v3.RoutingPriority_DEFAULT,
	MaxConnections:     wrapperspb.UInt32(math.MaxUint32),
	MaxPendingRequests: wrapperspb.UInt32(math.MaxUint32),
	MaxRequests:        wrapperspb.UInt32(math.MaxUint32),
	MaxConnectionPools: wrapperspb.UInt32(math.MaxUint32),
}

func buildInternalCircuitBreakers(cfg *config.Config) *envoy_config_cluster_v3.CircuitBreakers {
	threshold := unlimitedCircuitBreakersThreshold
	if cfg != nil && cfg.Options != nil {
		threshold = buildCircuitBreakersThreshold(threshold, cfg.Options.CircuitBreakerThresholds)
	}
	if threshold == nil {
		return nil
	}

	return &envoy_config_cluster_v3.CircuitBreakers{
		Thresholds: []*envoy_config_cluster_v3.CircuitBreakers_Thresholds{threshold},
	}
}

func buildRouteCircuitBreakers(cfg *config.Config, policy *config.Policy) *envoy_config_cluster_v3.CircuitBreakers {
	threshold := (*envoy_config_cluster_v3.CircuitBreakers_Thresholds)(nil)
	if cfg != nil && cfg.Options != nil {
		threshold = buildCircuitBreakersThreshold(threshold, cfg.Options.CircuitBreakerThresholds)
	}
	if policy != nil {
		threshold = buildCircuitBreakersThreshold(threshold, policy.CircuitBreakerThresholds)
	}

	if threshold == nil {
		return nil
	}

	return &envoy_config_cluster_v3.CircuitBreakers{
		Thresholds: []*envoy_config_cluster_v3.CircuitBreakers_Thresholds{threshold},
	}
}

func buildCircuitBreakersThreshold(dst *envoy_config_cluster_v3.CircuitBreakers_Thresholds, src *config.CircuitBreakerThresholds) *envoy_config_cluster_v3.CircuitBreakers_Thresholds {
	if src == nil {
		return dst
	}

	if dst == nil {
		dst = new(envoy_config_cluster_v3.CircuitBreakers_Thresholds)
	} else {
		dst = proto.CloneOf(dst)
	}

	if src.MaxConnections.IsSet() {
		dst.MaxConnections = wrapperspb.UInt32(src.MaxConnections.Uint32)
	}
	if src.MaxPendingRequests.IsSet() {
		dst.MaxPendingRequests = wrapperspb.UInt32(src.MaxPendingRequests.Uint32)
	}
	if src.MaxRequests.IsSet() {
		dst.MaxRequests = wrapperspb.UInt32(src.MaxRequests.Uint32)
	}
	if src.MaxRetries.IsSet() {
		dst.MaxRetries = wrapperspb.UInt32(src.MaxRetries.Uint32)
	}
	if src.MaxConnectionPools.IsSet() {
		dst.MaxConnectionPools = wrapperspb.UInt32(src.MaxConnectionPools.Uint32)
	}

	return dst
}
