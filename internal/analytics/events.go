package analytics

// An EventName is the name of an event.
type EventName string

// known events
var (
	EventNameBuiltEnvoyConfig EventName = "built_envoy_config"
)
