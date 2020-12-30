// Package netutil has helper types for working with network connections.
package netutil

import (
	"context"
	"net"
)

// Dialer is a type that has a DialContext method for making a network connection.
type Dialer = interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

type localDialer struct {
	underlying Dialer
	portToAddr map[string]string
}

// NewLocalDialer creates a new Dialer which routes localhost traffic to the remote destinations
// defined by `portToAddr`.
func NewLocalDialer(underlying Dialer, portToAddr map[string]string) Dialer {
	d := &localDialer{underlying: underlying, portToAddr: portToAddr}
	return d
}

func (d *localDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	addr = d.remapHost(ctx, addr)
	return d.underlying.DialContext(ctx, network, addr)
}

func (d *localDialer) remapHost(ctx context.Context, hostport string) string {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport
		port = "443"
	}

	dst, ok := d.portToAddr[port]
	if !ok {
		return hostport
	}

	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(ips) == 0 || ips[0].String() != "127.0.0.1" {
		return hostport
	}

	return dst
}
