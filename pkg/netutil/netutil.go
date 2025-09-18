// Package netutil contains various functions that help with networking.
package netutil

import (
	"fmt"
	"net/netip"

	"github.com/libp2p/go-reuseport"
)

// AllocateAddresses allocates random addresses suitable for listening.
func AllocateAddresses(count int) ([]netip.AddrPort, error) {
	var addrs []netip.AddrPort
	for len(addrs) < count {
		li, err := reuseport.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, fmt.Errorf("error starting listener: %w", err)
		}
		addr, err := netip.ParseAddrPort(li.Addr().String())
		defer li.Close()

		if err != nil {
			return nil, fmt.Errorf("error parsing listener address: %w", err)
		}
		addrs = append(addrs, addr)

	}
	return addrs, nil
}
