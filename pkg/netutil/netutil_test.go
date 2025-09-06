package netutil_test

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/pkg/netutil"
)

func TestAllocateAddresses(t *testing.T) {
	t.Parallel()

	addrs, err := netutil.AllocateAddresses(10)
	require.NoError(t, err)
	for _, addr := range addrs {
		a, err := netip.ParseAddrPort(addr)
		require.NoError(t, err)
		assert.True(t, a.Addr().IsLoopback())
	}
}

func TestRandomLoopbackIP(t *testing.T) {
	t.Parallel()

	for range 100 {
		ip := netutil.RandomLoopbackIP()
		addr, err := netip.ParseAddr(ip)
		assert.NoError(t, err)
		assert.True(t, addr.IsLoopback())
	}
}
