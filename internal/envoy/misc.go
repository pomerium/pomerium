package envoy

import (
	"fmt"
	"io/ioutil"
	"net"
	"strconv"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
)

const baseIDPath = "/tmp/pomerium-envoy-base-id"

func firstNonEmpty(args ...string) string {
	for _, a := range args {
		if a != "" {
			return a
		}
	}
	return ""
}

func readBaseID() (int, bool) {
	bs, err := ioutil.ReadFile(baseIDPath)
	if err != nil {
		return 0, false
	}

	baseID, err := strconv.Atoi(string(bs))
	if err != nil {
		return 0, false
	}

	return baseID, true
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
