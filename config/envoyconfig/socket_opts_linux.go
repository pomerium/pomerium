//go:build linux

package envoyconfig

import (
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"golang.org/x/sys/unix"
)

func getTCPListenerSocketOpts() []*envoy_config_core_v3.SocketOption {
	return []*envoy_config_core_v3.SocketOption{
		{
			Description: "TCP_USER_TIMEOUT ms",
			Level:       unix.IPPROTO_TCP,
			// Quickly detect IDLE unreachable connections and close them
			Name: unix.TCP_USER_TIMEOUT,
			Value: &envoy_config_core_v3.SocketOption_IntValue{
				// This is set to the same value as Timeout in grpc.ClientKeepaliveParams
				// and grpc.ServerKeepaliveParams for consistency
				IntValue: 20000,
			},
			State: envoy_config_core_v3.SocketOption_STATE_LISTENING,
		},
	}
}
