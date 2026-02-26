package mcp

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsInternalOrSpecial(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		// Private ranges (RFC 1918)
		{"10.0.0.1", "10.0.0.1", true},
		{"172.16.0.1", "172.16.0.1", true},
		{"192.168.1.1", "192.168.1.1", true},

		// Loopback
		{"loopback v4", "127.0.0.1", true},
		{"loopback v6", "::1", true},

		// Link-local
		{"link-local v4", "169.254.1.1", true},
		{"link-local v6", "fe80::1", true},

		// Multicast
		{"multicast v4", "224.0.0.1", true},
		{"multicast v6", "ff02::1", true},

		// Unspecified
		{"unspecified v4", "0.0.0.0", true},
		{"unspecified v6", "::", true},

		// IPv6 ULA
		{"ULA", "fd00::1", true},

		// v4-mapped v6 private
		{"v4-mapped private", "::ffff:10.0.0.1", true},
		{"v4-mapped loopback", "::ffff:127.0.0.1", true},

		// Public addresses
		{"public v4", "8.8.8.8", false},
		{"public v4 2", "1.1.1.1", false},
		{"public v6", "2607:f8b0:4004:800::200e", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ip := netip.MustParseAddr(tc.ip)
			assert.Equal(t, tc.expected, isInternalOrSpecial(ip))
		})
	}
}
