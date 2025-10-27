package portforward_test

import (
	"context"
	"errors"
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

func TestVirtualPortSet_Preempt(t *testing.T) {
	const size = 100
	vps := portforward.NewVirtualPortSet(size, 0)

	preemptedCtx0 := vps.Preempt(0)
	preemptedCtx1 := vps.Preempt(1)
	assert.Equal(t, uint(2), vps.Count())
	ports := [size]context.Context{}
	for range uint(size - 2) {
		p, ctx, err := vps.Get()
		require.NoError(t, err)
		assert.Less(t, p, uint(size))
		assert.GreaterOrEqual(t, p, uint(2))
		assert.True(t, vps.WithinRange(p))
		ports[p] = ctx
	}

	assert.Nil(t, ports[0])
	assert.Nil(t, ports[1])

	_, _, err := vps.Get()
	assert.ErrorIs(t, err, portforward.ErrNoFreePorts)

	err0 := errors.New("error 0")
	err1 := errors.New("error 1")
	vps.RemovePreemption(0, err0)
	vps.RemovePreemption(1, err1)

	assert.ErrorIs(t, context.Cause(preemptedCtx0), err0)
	assert.ErrorIs(t, context.Cause(preemptedCtx1), err1)
}

func TestVirtualPortSet_PreemptExisting(t *testing.T) {
	vps := portforward.NewVirtualPortSet(100, 0)
	port, ctx, err := vps.Get()
	require.NoError(t, err)
	preemptedCtx := vps.Preempt(port)
	assert.ErrorIs(t, context.Cause(ctx), portforward.ErrPortClosed)
	assert.NoError(t, context.Cause(preemptedCtx))
	cause := errors.New("test error")
	vps.RemovePreemption(port, cause)
	assert.ErrorIs(t, context.Cause(preemptedCtx), cause)
}

func TestVirtualPortSet_PreemptErrors(t *testing.T) {
	t.Run("incorrect usage", func(t *testing.T) {
		vps := portforward.NewVirtualPortSet(100, 0)
		_ = vps.Preempt(1)
		assert.Panics(t, func() {
			vps.Put(1)
		})
	})

	t.Run("out of range", func(t *testing.T) {
		vps := portforward.NewVirtualPortSet(100, 0)
		assert.Panics(t, func() {
			vps.Preempt(100)
		})
	})

	t.Run("already preempted", func(t *testing.T) {
		vps := portforward.NewVirtualPortSet(100, 0)
		vps.Preempt(99)
		assert.Panics(t, func() {
			vps.Preempt(99)
		})
	})

	t.Run("remove out of range", func(t *testing.T) {
		vps := portforward.NewVirtualPortSet(100, 0)
		assert.Panics(t, func() {
			vps.RemovePreemption(100, errors.New("cause"))
		})
	})

	t.Run("remove not preempted", func(t *testing.T) {
		vps := portforward.NewVirtualPortSet(100, 0)
		assert.Panics(t, func() {
			vps.RemovePreemption(99, errors.New("cause"))
		})
	})
}
