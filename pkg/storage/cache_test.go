package storage

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestGlobalCache(t *testing.T) {
	ctx, clearTimeout := context.WithTimeout(t.Context(), time.Second*10)
	defer clearTimeout()

	callCount := 0
	update := func(_ context.Context) ([]byte, error) {
		callCount++
		return []byte("v1"), nil
	}
	c := NewGlobalCache(time.Millisecond * 100)
	v, err := c.GetOrUpdate(ctx, []byte("k1"), update)
	assert.NoError(t, err)
	assert.Equal(t, []byte("v1"), v)
	assert.Equal(t, 1, callCount)

	v, err = c.GetOrUpdate(ctx, []byte("k1"), update)
	assert.NoError(t, err)
	assert.Equal(t, []byte("v1"), v)
	assert.Equal(t, 1, callCount)

	c.Invalidate([]byte("k1"))

	v, err = c.GetOrUpdate(ctx, []byte("k1"), update)
	assert.NoError(t, err)
	assert.Equal(t, []byte("v1"), v)
	assert.Equal(t, 2, callCount)

	assert.Eventually(t, func() bool {
		_, err := c.GetOrUpdate(ctx, []byte("k1"), func(_ context.Context) ([]byte, error) {
			return nil, fmt.Errorf("ERROR")
		})
		return err != nil
	}, time.Second, time.Millisecond*10, "should honor TTL")

	c.Set(time.Now().Add(time.Hour), []byte("k2"), []byte("v2"))
	v, err = c.GetOrUpdate(ctx, []byte("k2"), update)
	assert.NoError(t, err)
	assert.Equal(t, []byte("v2"), v)
	assert.Equal(t, 2, callCount)
}
