package config

// GRPCDatabrokerKeepalive enables gRPC keepalive to the databroker service
var GRPCDatabrokerKeepalive = runtimeFlag("grpc_databroker_keepalive", false)

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
	out := make(RuntimeFlags, len(defaultRuntimeFlags))
	for k, v := range defaultRuntimeFlags {
		out[k] = v
	}
	return out
}
