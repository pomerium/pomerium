// Package netutil contains various functions that help with networking.
package netutil

import (
	"net"
	"sync"
	"time"
)

var (
	allocatedPortsMu sync.Mutex
	allocatedPorts   = map[string]time.Time{}
)

// AllocatePorts allocates random ports suitable for listening.
func AllocatePorts(count int) ([]string, error) {
	allocatedPortsMu.Lock()
	defer allocatedPortsMu.Unlock()

	now := time.Now()
	cooloff := 10 * time.Minute
	// clear any expired ports
	for port, tm := range allocatedPorts {
		if tm.Add(cooloff).Before(now) {
			delete(allocatedPorts, port)
		}
	}

	var ports []string
	for len(ports) < count {
		li, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		_, port, _ := net.SplitHostPort(li.Addr().String())
		defer li.Close()

		// if this port has been allocated recently, skip it
		if _, ok := allocatedPorts[port]; ok {
			continue
		}

		allocatedPorts[port] = now
		ports = append(ports, port)
	}
	return ports, nil
}
