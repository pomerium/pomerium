// Package netutil contains various functions that help with networking.
package netutil

import (
	"fmt"
	"strconv"
)

var defaultPortAllocator = NewFailoverPortAllocator(NewBlockPortAllocator(), NewEphemeralBindPortAllocator())

// AllocatePorts allocates random ports suitable for listening.
func AllocatePorts(count int) ([]string, error) {
	ports := make([]string, count)
	for i := range ports {
		p, ok := defaultPortAllocator.AllocatePort()
		if !ok {
			return nil, fmt.Errorf("failed to allocate ports")
		}
		ports[i] = strconv.FormatUint(uint64(p), 10)
	}
	return ports, nil
}
