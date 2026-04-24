package envoyconfig

import (
	envoy_config_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	"github.com/pomerium/pomerium/config"
)

// BuildRateLimitActions creates Envoy rate limit actions for a route.
func BuildRateLimitActions(route *config.Policy) []*envoy_config_route_v3.RateLimit {
	if route.RateLimit == nil {
		return nil
	}

	// Default to destination_service (route ID)
	descriptorKey := "destination_service"
	descriptorValue := route.ID

	if route.RateLimit.DescriptorKey != "" {
		descriptorKey = route.RateLimit.DescriptorKey
		descriptorValue = route.RateLimit.DescriptorValue
	}

	return []*envoy_config_route_v3.RateLimit{
		{
			Actions: []*envoy_config_route_v3.RateLimit_Action{
				{
					ActionSpecifier: &envoy_config_route_v3.RateLimit_Action_GenericKey_{
						GenericKey: &envoy_config_route_v3.RateLimit_Action_GenericKey{
							DescriptorKey:   descriptorKey,
							DescriptorValue: descriptorValue,
						},
					},
				},
			},
		},
	}
}

// HasRouteRateLimiting checks if any route has rate limiting configured.
func HasRouteRateLimiting(cfg *config.Config) bool {
	for route := range cfg.Options.GetAllPolicies() {
		if route.RateLimit != nil {
			return true
		}
	}
	return false
}