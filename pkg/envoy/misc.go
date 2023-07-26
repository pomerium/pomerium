package envoy

import (
	"fmt"
	"net"
	"strconv"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
)

func firstNonEmpty[T interface{ ~string }](args ...T) T {
	for _, a := range args {
		if a != "" {
			return a
		}
	}
	return ""
}

// ParseAddress parses a string address into an envoy address.
func ParseAddress(raw string) (*envoy_config_core_v3.Address, error) {
	if host, portstr, err := net.SplitHostPort(raw); err == nil {
		if port, err := strconv.Atoi(portstr); err == nil {
			return &envoy_config_core_v3.Address{
				Address: &envoy_config_core_v3.Address_SocketAddress{
					SocketAddress: &envoy_config_core_v3.SocketAddress{
						Address: host,
						PortSpecifier: &envoy_config_core_v3.SocketAddress_PortValue{
							PortValue: uint32(port),
						},
					},
				},
			}, nil
		}
	}
	return nil, fmt.Errorf("unknown address format: %s", raw)
}
