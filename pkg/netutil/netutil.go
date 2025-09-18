// Package netutil contains various functions that help with networking.
package netutil

import (
	"net/netip"

	"github.com/libp2p/go-reuseport"
)

// AllocateAddresses allocates random addresses suitable for listening.
func AllocateAddresses(count int) ([]netip.AddrPort, error) {
	var addrs []netip.AddrPort
	for len(addrs) < count {
		li, err := reuseport.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		addr := netip.MustParseAddrPort(li.Addr().String())
		defer li.Close()

		addrs = append(addrs, addr)

	}
	return addrs, nil
}
