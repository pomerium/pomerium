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
			Name:        unix.TCP_USER_TIMEOUT,
			Value: &envoy_config_core_v3.SocketOption_IntValue{
				IntValue: 20000,
			},
			State: envoy_config_core_v3.SocketOption_STATE_LISTENING,
		},
	}
}
