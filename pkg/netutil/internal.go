package netutil

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"github.com/google/uuid"
)

// An InternalAddress is an address suitable for communication between internal
// Pomerium components or between Pomerium and Envoy.
type InternalAddress struct {
	URL url.URL
}

// NewInternalAddress creates a new internal address.
func NewInternalAddress() *InternalAddress {
	path := GetUnixSocketPath(uuid.NewString())
	return NewInternalAddressForUnixSocket(path)
}

// NewInternalAddressForTCP creates a new internal address
// from a tcp address and port.
func NewInternalAddressForTCP(addrPort netip.AddrPort) *InternalAddress {
	return &InternalAddress{URL: url.URL{
		Scheme: "tcp",
		Host:   addrPort.String(),
	}}
}

// NewInternalAddressForUnixSocket creates a new internal address
// from a unix socket path.
func NewInternalAddressForUnixSocket(path string) *InternalAddress {
	if strings.HasPrefix(path, "@") {
		return &InternalAddress{URL: url.URL{
			Scheme: "unix-abstract",
			Opaque: path[1:],
		}}
	}
	return &InternalAddress{URL: url.URL{
		Scheme: "unix",
		Opaque: path,
	}}
}

// Dial creates a network connection for the internal address.
func (a *InternalAddress) Dial(ctx context.Context) (net.Conn, error) {
	switch a.URL.Scheme {
	case "tcp":
		return (&net.Dialer{}).DialContext(ctx, "tcp", a.URL.Host)
	case "unix":
		return (&net.Dialer{}).DialContext(ctx, "unix", a.URL.Opaque)
	case "unix-abstract":
		return (&net.Dialer{}).DialContext(ctx, "unix", "@"+a.URL.Opaque)
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
					Path: a.URL.Opaque,
					Mode: 0o0600,
				},
			},
		}
	case "unix-abstract":
		return &envoy_config_core_v3.Address{
			Address: &envoy_config_core_v3.Address_Pipe{
				Pipe: &envoy_config_core_v3.Pipe{
					Path: "@" + a.URL.Opaque,
				},
			},
		}
	default:
		panic(fmt.Sprintf("unsupported internal address: %s", a))
	}
}

// Listen starts a net listener for the internal address.
func (a *InternalAddress) Listen(ctx context.Context) (net.Listener, error) {
	switch a.URL.Scheme {
	case "tcp":
		return (&net.ListenConfig{}).Listen(ctx, "tcp", a.URL.Host)
	case "unix":
		return (&net.ListenConfig{}).Listen(ctx, "unix", a.URL.Opaque)
	case "unix-abstract":
		return (&net.ListenConfig{}).Listen(ctx, "unix", "@"+a.URL.Opaque)
	default:
		panic(fmt.Sprintf("unsupported internal address: %s", a))
	}
}

func (a *InternalAddress) String() string {
	return a.URL.String()
}
