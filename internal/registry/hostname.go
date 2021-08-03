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

func chooseIP(ips []net.IP) net.IP {
	for _, ip := range ips {
		if !ip.IsLoopback() && !ip.IsInterfaceLocalMulticast() && !ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast() {
			return ip
		}
	}
	return nil
}

// getViaLookup tries to lookup whether short hostname may be resolved into IP and back into a longer one
func getViaLookup(host string) (string, error) {
	addrs, err := net.LookupIP(host)
	if err != nil {
		return "", err
	}
	if len(addrs) == 0 {
		return "", errors.New("address lookup failed")
	}
	for _, addr := range addrs {
		hosts, err := net.LookupAddr(addr.String())
		if err != nil {
			continue
		}
		for _, h := range hosts {
			h = strings.TrimSuffix(h, ".")
			if isFQDN(h) {
				return h, nil
			}
		}
	}

	if ip := chooseIP(addrs); ip != nil {
		return ip.String(), nil
	}
	return "", errors.New("lookup failed")
}

// getHostOrIP tries to fetch a publicly accessible IP address for the current host/container
func getHostOrIP() (string, error) {
	host, err := os.Hostname()
	if err != nil {
		return "", fmt.Errorf("hostname: %w", err)
	}
	if isFQDN(host) {
		return host, nil
	}

	if h, err := getViaLookup(host); err == nil {
		return h, nil
	}

	return host, nil
}
