package envoyconfig

import (
	envoy_config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"

	"github.com/pomerium/pomerium/config"
)

func buildRouteOutlierDetection(src *config.Policy) *envoy_config_cluster_v3.OutlierDetection {
	if src.OutlierDetection == nil {
		return nil
	}
	return &envoy_config_cluster_v3.OutlierDetection{
		Consecutive_5Xx:                        src.OutlierDetection.Consecutive_5Xx,
		Interval:                               src.OutlierDetection.Interval,
		BaseEjectionTime:                       src.OutlierDetection.BaseEjectionTime,
		MaxEjectionPercent:                     src.OutlierDetection.MaxEjectionPercent,
		EnforcingConsecutive_5Xx:               src.OutlierDetection.EnforcingConsecutive_5Xx,
		EnforcingSuccessRate:                   src.OutlierDetection.EnforcingSuccessRate,
		SuccessRateMinimumHosts:                src.OutlierDetection.SuccessRateMinimumHosts,
		SuccessRateRequestVolume:               src.OutlierDetection.SuccessRateRequestVolume,
		SuccessRateStdevFactor:                 src.OutlierDetection.SuccessRateStdevFactor,
		ConsecutiveGatewayFailure:              src.OutlierDetection.ConsecutiveGatewayFailure,
		EnforcingConsecutiveGatewayFailure:     src.OutlierDetection.EnforcingConsecutiveGatewayFailure,
		SplitExternalLocalOriginErrors:         src.OutlierDetection.SplitExternalLocalOriginErrors,
		ConsecutiveLocalOriginFailure:          src.OutlierDetection.ConsecutiveLocalOriginFailure,
		EnforcingConsecutiveLocalOriginFailure: src.OutlierDetection.EnforcingConsecutiveLocalOriginFailure,
		EnforcingLocalOriginSuccessRate:        src.OutlierDetection.EnforcingLocalOriginSuccessRate,
		FailurePercentageThreshold:             src.OutlierDetection.FailurePercentageThreshold,
		EnforcingFailurePercentage:             src.OutlierDetection.EnforcingFailurePercentage,
		EnforcingFailurePercentageLocalOrigin:  src.OutlierDetection.EnforcingFailurePercentageLocalOrigin,
		FailurePercentageMinimumHosts:          src.OutlierDetection.FailurePercentageMinimumHosts,
		FailurePercentageRequestVolume:         src.OutlierDetection.FailurePercentageRequestVolume,
		MaxEjectionTime:                        src.OutlierDetection.MaxEjectionTime,
		MaxEjectionTimeJitter:                  src.OutlierDetection.MaxEjectionTimeJitter,
		SuccessfulActiveHealthCheckUnejectHost: src.OutlierDetection.SuccessfulActiveHealthCheckUnejectHost,
		AlwaysEjectOneHost:                     src.OutlierDetection.AlwaysEjectOneHost,
	}
}
