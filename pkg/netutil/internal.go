package netutil

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"sync/atomic"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
)

type InternalAddress struct {
	URL url.URL
}

func (a *InternalAddress) DialContext(ctx context.Context) (net.Conn, error) {
	switch a.URL.Scheme {
	case "tcp":
		return (&net.Dialer{}).DialContext(ctx, "tcp", a.URL.Host)
	case "unix":
		return (&net.Dialer{}).DialContext(ctx, "unix", a.URL.Host)
	default:
		panic(fmt.Sprintf("unsupported internal address: %s", a))
	}
}

func (a *InternalAddress) EnvoyAddress() *envoy_config_core_v3.Address {
	switch a.URL.Scheme {
	case "tcp":
		addrPort := netip.MustParseAddrPort("127.0.0.1:0")
		if v, err := netip.ParseAddrPort(a.URL.Host); err == nil {
			addrPort = v
		} else if v, err := netip.ParseAddr(a.URL.Host); err == nil {
			addrPort = netip.AddrPortFrom(v, 0)
		}
		return &envoy_config_core_v3.Address{
			Address: &envoy_config_core_v3.Address_SocketAddress{
				SocketAddress: &envoy_config_core_v3.SocketAddress{
					Protocol: *envoy_config_core_v3.SocketAddress_TCP.Enum(),
					Address:  addrPort.Addr().String(),
					PortSpecifier: &envoy_config_core_v3.SocketAddress_PortValue{
						PortValue: uint32(addrPort.Port()),
					},
				},
			},
		}
	case "unix":
		return &envoy_config_core_v3.Address{
			Address: &envoy_config_core_v3.Address_Pipe{
				Pipe: &envoy_config_core_v3.Pipe{
					Path: a.URL.Host,
					Mode: 0o0600,
				},
			},
		}
	default:
		panic(fmt.Sprintf("unsupported internal address: %s", a))
	}
}

func (a *InternalAddress) String() string {
	return a.URL.String()
}

var internalAddressCount atomic.Int64

// NewInternalAddress creates a new address suitable for internal
// communication between Pomerium and envoy.
func NewInternalAddress(name string) *InternalAddress {
	id := internalAddressCount.Add(1)
	fullName := fmt.Sprintf("pomerium-%s-%x", name, id)
	return &InternalAddress{URL: url.URL{
		Scheme: "unix",
		Host:   GetUnixSocketPath(fullName),
	}}
}
