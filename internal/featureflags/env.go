// Package featureflags enables feature flags that are set via environment variables.
// the feature flags are used to enable or disable experimental or debug features.
// there are no guarantees of stability or backward compatibility for these features.
package featureflags

import (
	"fmt"
	"os"
	"strconv"
)

var (
	// GRPCLogConnectionState connection logs gRPC connection state transitions
	// which is less verbose than logs enabled via https://github.com/grpc/grpc-go/blob/master/README.md#how-to-turn-on-logging
	GRPCLogConnectionState = option("GRPC_LOG_CONNECTION_STATE", false)
	// GRPCConnectKeepalive enables gRPC keepalive to zero connect service
	GRPCConnectKeepalive = option("GRPC_CONNECT_KEEPALIVE", true)
	// GRPCDatabrokerKeepalive enables gRPC keepalive to the databroker service
	GRPCDatabrokerKeepalive = option("GRPC_DATABROKER_KEEPALIVE", false)
)

// Option is a feature flag option.
type Option string

func option(name string, defaultValue bool) Option {
	k := Option(name)
	flags[k] = defaultValue
	return k
}

var flags = make(map[Option]bool)

func init() {
	for k := range flags {
		if txt, ok := os.LookupEnv(fmt.Sprintf("POMERIUM_%s", k)); ok {
			v, err := strconv.ParseBool(txt)
			if err == nil {
				flags[k] = v
			}
		}
	}
}

// IsSet returns true if the feature flag is set.
func IsSet(k Option) bool {
	return flags[k]
}

// Flags returns the current feature flags
func Flags() map[string]bool {
	dst := make(map[string]bool, len(flags))
	for k, v := range flags {
		dst[string(k)] = v
	}
	return dst
}
