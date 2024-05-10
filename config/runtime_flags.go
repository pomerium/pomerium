package config

import "golang.org/x/exp/maps"

var (
	// RuntimeFlagGRPCDatabrokerKeepalive enables gRPC keepalive to the databroker service
	RuntimeFlagGRPCDatabrokerKeepalive = runtimeFlag("grpc_databroker_keepalive", false)

	// RuntimeFlagMatchAnyIncomingPort enables ignoring the incoming port when matching routes
	RuntimeFlagMatchAnyIncomingPort = runtimeFlag("match_any_incoming_port", true)

	// RuntimeFlagLegacyIdentityManager enables the legacy identity manager
	RuntimeFlagLegacyIdentityManager = runtimeFlag("legacy_identity_manager", false)

	RuntimeFlagEnvoyResourceManagerEnabled = runtimeFlag("envoy_resource_manager_enabled", true)
)

// RuntimeFlag is a runtime flag that can flip on/off certain features
type RuntimeFlag string

// RuntimeFlags is a map of runtime flags
type RuntimeFlags map[RuntimeFlag]bool

func runtimeFlag(txt string, def bool) RuntimeFlag {
	key := RuntimeFlag(txt)
	defaultRuntimeFlags[key] = def
	return key
}

var defaultRuntimeFlags = map[RuntimeFlag]bool{}

func DefaultRuntimeFlags() RuntimeFlags {
	return maps.Clone(defaultRuntimeFlags)
}
