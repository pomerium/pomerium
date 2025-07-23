//go:build linux

package envoyconfig

import (
	"syscall"

	"golang.org/x/sys/unix"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
)

func addIPBindAddressNoPortSocketOption(opts *[]*envoy_config_core_v3.SocketOption) {
	*opts = append(*opts, &envoy_config_core_v3.SocketOption{
		Description: "IP_BIND_ADDRESS_NO_PORT",
		Level:       syscall.IPPROTO_IP,
		Name:        unix.IP_BIND_ADDRESS_NO_PORT,
		Value:       &envoy_config_core_v3.SocketOption_IntValue{IntValue: 1},
		State:       envoy_config_core_v3.SocketOption_STATE_PREBIND,
	})
}
