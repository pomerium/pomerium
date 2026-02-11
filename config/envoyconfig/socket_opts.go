//go:build !linux

package envoyconfig

import (
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
)

func getTCPListenerSocketOpts() []*envoy_config_core_v3.SocketOption {
	return nil
}
