// Package netutil contains various functions that help with networking.
package netutil

import (
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"runtime"
	"testing"
)

// AllocateAddresses allocates random addresses suitable for listening.
func AllocateAddresses(count int) ([]netip.AddrPort, error) {
	var addrs []netip.AddrPort
	for len(addrs) < count {
		addr := netip.AddrFrom4([4]byte{127, 0, 0, 1})
		if testing.Testing() && runtime.GOOS != "darwin" { // macos doesn't seem to like random loopback addresses
			addr = RandomIPv4LoopbackAddress()
		}
		li, err := net.Listen("tcp4", fmt.Sprintf("%s:0", addr.String()))
		if err != nil {
			return nil, fmt.Errorf("error starting listener: %w", err)
		}
		addrPort, err := netip.ParseAddrPort(li.Addr().String())
		defer li.Close()

		if err != nil {
			return nil, fmt.Errorf("error parsing listener address: %w", err)
		}
		addrs = append(addrs, addrPort)
	}
	return addrs, nil
}

// AllocatePorts allocates ports for the given address.
func AllocatePorts(addr netip.Addr, count int) ([]netip.AddrPort, error) {
	var addrs []netip.AddrPort
	for len(addrs) < count {
		li, err := net.Listen("tcp", fmt.Sprintf("%s:0", addr.String()))
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

// RandomIPv4LoopbackAddress returns a random ipv4 loopback address.
func RandomIPv4LoopbackAddress() netip.Addr {
	minAddr := netip.AddrFrom4([4]byte{127, 0, 0, 1})
	maxAddr := netip.AddrFrom4([4]byte{127, 255, 255, 254})

	minUint32 := binary.BigEndian.Uint32(minAddr.AsSlice())
	maxUint32 := binary.BigEndian.Uint32(maxAddr.AsSlice())

	v := minUint32 + rand.Uint32N((maxUint32+1)-minUint32) //nolint:gosec
	var bs [4]byte
	binary.BigEndian.PutUint32(bs[:], v)
	return netip.AddrFrom4(bs)
}
