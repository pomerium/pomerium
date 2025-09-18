package netutil_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/pkg/netutil"
)

func TestAllocateAddresses(t *testing.T) {
	t.Parallel()

	addrs, err := netutil.AllocateAddresses(10)
	assert.NoError(t, err)
	assert.Len(t, addrs, 10)
	for _, addr := range addrs {
		assert.True(t, addr.Addr().IsLoopback())
	}
}
