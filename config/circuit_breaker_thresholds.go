package config

import (
	"github.com/volatiletech/null/v9"

	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
)

// CircuitBreakerThresholds define thresholds for circuit breaking.
type CircuitBreakerThresholds struct {
	MaxConnections     null.Uint32 `mapstructure:"max_connections" yaml:"max_connections,omitempty" json:"max_connections,omitempty"`
	MaxPendingRequests null.Uint32 `mapstructure:"max_pending_requests" yaml:"max_pending_requests,omitempty" json:"max_pending_requests,omitempty"`
	MaxRequests        null.Uint32 `mapstructure:"max_requests" yaml:"max_requests,omitempty" json:"max_requests,omitempty"`
	MaxRetries         null.Uint32 `mapstructure:"max_retries" yaml:"max_retries,omitempty" json:"max_retries,omitempty"`
	MaxConnectionPools null.Uint32 `mapstructure:"max_connection_pools" yaml:"max_connection_pools,omitempty" json:"max_connection_pools,omitempty"`
}

// CircuitBreakerThresholdsFromPB converts the CircuitBreakerThresholds from a protobuf type.
func CircuitBreakerThresholdsFromPB(src *configpb.CircuitBreakerThresholds) *CircuitBreakerThresholds {
	if src == nil {
		return nil
	}

	dst := &CircuitBreakerThresholds{}
	if src.MaxConnections != nil {
		dst.MaxConnections = null.Uint32From(*src.MaxConnections)
	}
	if src.MaxPendingRequests != nil {
		dst.MaxPendingRequests = null.Uint32From(*src.MaxPendingRequests)
	}
	if src.MaxRequests != nil {
		dst.MaxRequests = null.Uint32From(*src.MaxRequests)
	}
	if src.MaxRetries != nil {
		dst.MaxRetries = null.Uint32From(*src.MaxRetries)
	}
	if src.MaxConnectionPools != nil {
		dst.MaxConnectionPools = null.Uint32From(*src.MaxConnectionPools)
	}
	return dst
}

// CircuitBreakerThresholdsToPB converts the CircuitBreakerThresholds into a protobuf type.
func CircuitBreakerThresholdsToPB(src *CircuitBreakerThresholds) *configpb.CircuitBreakerThresholds {
	if src == nil {
		return nil
	}

	return &configpb.CircuitBreakerThresholds{
		MaxConnections:     src.MaxConnections.Ptr(),
		MaxPendingRequests: src.MaxPendingRequests.Ptr(),
		MaxRequests:        src.MaxRequests.Ptr(),
		MaxRetries:         src.MaxRetries.Ptr(),
		MaxConnectionPools: src.MaxConnectionPools.Ptr(),
	}
}
