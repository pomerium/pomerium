package registry

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
)

func isFQDN(host string) bool {
	return strings.Count(host, ".") > 1
}

// getViaLookup tries to lookup whether short hostname may be resolved into IP and back into a longer one
func getViaLookup(host string) (string, error) {
	addrs, err := net.LookupHost(host)
	if err != nil {
		return "", err
	}
	if len(addrs) == 0 {
		return "", errors.New("address lookup failed")
	}
	for _, addr := range addrs {
		hosts, err := net.LookupAddr(addr)
		if err != nil {
			continue
		}
		for _, h := range hosts {
			if isFQDN(h) {
				return h, nil
			}
		}
	}
	return addrs[0], nil
}

// getExternalHostOrIP tries to fetch a publicly accessible IP address for the current host/container
func getExternalHostOrIP(port string) (string, error) {
	host, err := os.Hostname()
	if err != nil {
		return "", fmt.Errorf("hostname: %w", err)
	}
	if isFQDN(host) {
		return host, nil
	}

	return getViaLookup(host)
}
