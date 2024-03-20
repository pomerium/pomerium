// Package featureflags enables feature flags that are set via environment variables.
// the feature flags are used to enable or disable experimental features.
package featureflags

import (
	"fmt"
	"os"
)

const (
	// GRPCLogConnectionState connection logs gRPC connection state transitions
	// which is less verbose than logs enabled via https://github.com/grpc/grpc-go/blob/master/README.md#how-to-turn-on-logging
	GRPCLogConnectionState = "GRPC_LOG_CONNECTION_STATE"
	// GRPCConnectDisableKeepalive disables gRPC keepalive to zero connect service
	GRPCConnectDisableKeepalive = "GRPC_CONNECT_DISABLE_KEEPALIVE"
)

var flags = make(map[string]struct{})

func init() {
	for _, env := range []string{
		GRPCLogConnectionState,
	} {
		if _, ok := os.LookupEnv(fmt.Sprintf("POMERIUM_%s", env)); ok {
			flags[env] = struct{}{}
		}
	}
}

// IsSet returns true if the feature flag is set.
func IsSet(flag string) bool {
	_, ok := flags[flag]
	return ok
}
