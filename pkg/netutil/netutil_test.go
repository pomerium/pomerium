package netutil_test

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/pkg/netutil"
)

func TestRandomLoopbackIP(t *testing.T) {
	t.Parallel()

	for range 100 {
		ip := netutil.RandomLoopbackIP()
		addr, err := netip.ParseAddr(ip)
		assert.NoError(t, err)
		assert.True(t, addr.IsLoopback())
	}
}
