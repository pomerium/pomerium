// Package netutil contains various functions that help with networking.
package netutil

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/big"
	"net"
	"net/netip"

	"golang.org/x/sync/errgroup"
)

// AllocateAddresses allocates random addresses suitable for listening.
func AllocateAddresses(count int) ([]string, error) {
	addresses := make([]string, count)
	var eg errgroup.Group
	for i := range count {
		eg.Go(func() error {
			li, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				return err
			}
			_, port, err := net.SplitHostPort(li.Addr().String())
			_ = li.Close()
			addresses[i] = fmt.Sprintf("%s:%s", RandomLoopbackIP(), port)
			return err
		})
	}
	return addresses, eg.Wait()
}

// AllocatePorts allocates random ports suitable for listening.
func AllocatePorts(count int) ([]string, error) {
	var ports []string
	for len(ports) < count {
		li, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		_, port, _ := net.SplitHostPort(li.Addr().String())
		defer li.Close()

		ports = append(ports, port)
	}
	return ports, nil
}

var (
	minIP = addrToBigInt(netip.AddrFrom4([4]byte{127, 0, 0, 2}))
	maxIP = addrToBigInt(netip.AddrFrom4([4]byte{127, 255, 255, 254}))
)

// RandomLoopbackIP returns a random loopback ip.
func RandomLoopbackIP() string {
	diff := big.NewInt(0).Sub(maxIP, minIP)
	n, err := rand.Int(rand.Reader, diff)
	if err != nil {
		panic(err)
	}
	return addrFromBigInt(big.NewInt(0).Add(minIP, n)).String()
}

func addrFromBigInt(i *big.Int) netip.Addr {
	var bs [4]byte
	binary.BigEndian.PutUint32(bs[:], uint32(i.Uint64()))
	return netip.AddrFrom4(bs)
}

func addrToBigInt(addr netip.Addr) *big.Int {
	return big.NewInt(int64(binary.BigEndian.Uint32(addr.AsSlice())))
}
