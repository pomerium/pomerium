//go:build !linux

package envoyconfig

import (
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
)

func addIPBindAddressNoPortSocketOption(_ *[]*envoy_config_core_v3.SocketOption) {
	// This socket option is supported only on Linux.
}
