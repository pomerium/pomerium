// Package netutil contains various functions that help with networking.
package netutil

import "net"

// AllocatePorts allocates random ports suitable for listening.
func AllocatePorts(count int) ([]int, error) {
	// based on https://github.com/tendermint/tendermint/issues/3682#issuecomment-497333084
	ports := make([]int, count)

	for k := range ports {
		addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
		if err != nil {
			return nil, err
		}

		l, err := net.ListenTCP("tcp", addr)
		if err != nil {
			return nil, err
		}
		// This is done on purpose - we want to keep ports
		// busy to avoid collisions when getting the next one
		defer func() { _ = l.Close() }()
		ports[k] = l.Addr().(*net.TCPAddr).Port
	}

	return ports, nil
}
