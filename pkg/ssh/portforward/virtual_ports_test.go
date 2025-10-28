package portforward_test

import (
	"context"
	"testing"

	"github.com/pomerium/pomerium/pkg/ssh/portforward"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVirtualPortSet(t *testing.T) {
	const size = 100
	for offset := range uint(100) {
		vps := portforward.NewVirtualPortSet(size, offset)
		assert.Equal(t, uint(0), vps.Count())
		ports := [size]context.Context{}
		for range size {
			p, ctx, err := vps.Get()
			require.NoError(t, err)
			assert.Less(t, p, size+offset)
			assert.GreaterOrEqual(t, p, offset)
			assert.True(t, vps.WithinRange(p))
			ports[p-offset] = ctx
		}
		assert.Equal(t, uint(size), vps.Count())
		_, _, err := vps.Get()
		assert.ErrorIs(t, err, portforward.ErrNoFreePorts)
		for _, ctx := range ports {
			require.NotNil(t, ctx)
			assert.NoError(t, context.Cause(ctx))
		}
		for i := range uint(size) {
			vps.Put(uint(i + offset))
			assert.ErrorIs(t, context.Cause(ports[i]), portforward.ErrPortClosed)
			assert.Equal(t, uint(size-i-1), vps.Count())
		}
	}
}

func TestVirtualPortSet_PutErrors(t *testing.T) {
	const size = 100
	vps := portforward.NewVirtualPortSet(size, 0)
	assert.PanicsWithValue(t, "bug: Put called with out-of-range port 100", func() {
		vps.Put(size)
	})
	assert.PanicsWithValue(t, "bug: port was never allocated", func() {
		vps.Put(1)
	})
}

func TestVirtualPortSet_MustGet(t *testing.T) {
	const size = 100
	vps := portforward.NewVirtualPortSet(size, 0)
	for range 100 {
		vps.MustGet()
	}
	assert.Panics(t, func() { vps.MustGet() })
}
