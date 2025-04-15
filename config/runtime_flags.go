package config

import "maps"

var (
	// RuntimeFlagConfigHotReload enables the hot-reloading mechanism for the config file
	// and any other files referenced within it
	RuntimeFlagConfigHotReload = runtimeFlag("config_hot_reload", true)

	// RuntimeFlagEnvoyResourceManager enables Envoy overload settings based on
	// process cgroup limits (Linux only).
	RuntimeFlagEnvoyResourceManager = runtimeFlag("envoy_resource_manager", true)

	// RuntimeFlagGRPCDatabrokerKeepalive enables gRPC keepalive to the databroker service
	RuntimeFlagGRPCDatabrokerKeepalive = runtimeFlag("grpc_databroker_keepalive", false)

	// RuntimeFlagMatchAnyIncomingPort enables ignoring the incoming port when matching routes
	RuntimeFlagMatchAnyIncomingPort = runtimeFlag("match_any_incoming_port", true)

	// RuntimeFlagPomeriumJWTEndpoint enables the /.pomerium/jwt endpoint, for retrieving
	// signed user info claims from an upstream single-page web application. This endpoint
	// is deprecated pending removal in a future release, but this flag allows a temporary
	// opt-out from the deprecation.
	RuntimeFlagPomeriumJWTEndpoint = runtimeFlag("pomerium_jwt_endpoint", false)

	// RuntimeFlagAddExtraMetricsLabels enables adding extra labels to metrics (host and installation id)
	RuntimeFlagAddExtraMetricsLabels = runtimeFlag("add_extra_metrics_labels", true)

	// RuntimeFlagAuthorizeUseSyncedData enables synced data for querying the databroker for
	// certain types of data.
	RuntimeFlagAuthorizeUseSyncedData = runtimeFlag("authorize_use_synced_data", true)
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
