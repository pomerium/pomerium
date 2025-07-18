// Package netutil contains various functions that help with networking.
package netutil

import (
	"net"

	"github.com/libp2p/go-reuseport"
)

// AllocatePorts allocates random ports suitable for listening.
func AllocatePorts(count int) ([]string, error) {
	var ports []string
	for len(ports) < count {
		li, err := reuseport.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		_, port, _ := net.SplitHostPort(li.Addr().String())
		defer li.Close()

		ports = append(ports, port)
	}
	return ports, nil
}
