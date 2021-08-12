// Package netutil contains various functions that help with networking.
package netutil

import "net"

// AllocatePorts allocates random ports suitable for listening.
func AllocatePorts(count int) ([]string, error) {
	var ports []string
	for i := 0; i < count; i++ {
		li, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		_, port, _ := net.SplitHostPort(li.Addr().String())
		err = li.Close()
		if err != nil {
			return nil, err
		}
		ports = append(ports, port)
	}
	return ports, nil
}
