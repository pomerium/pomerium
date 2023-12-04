package counter_test

import (
	"fmt"
	"math"
	"math/rand"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/pkg/counter"
)

func stableRandomUUIDs(n int) []string {
	r := rand.New(rand.NewSource(1234567890))
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		u, _ := uuid.NewRandomFromReader(r)
		out = append(out, u.String())
	}
	return out
}

func TestStableRandomUUIDs(t *testing.T) {
	t.Parallel()

	assert.Equal(t, stableRandomUUIDs(20), stableRandomUUIDs(20))
}

func TestCounter(t *testing.T) {
	t.Parallel()

	limit := 1000
	n := (limit * 8) / 10
	for j := 0; j < 20; j++ {
		t.Run(fmt.Sprint(j), func(t *testing.T) {
			c := counter.New(uint(limit))
			for _, id := range stableRandomUUIDs(n) {
				c.Mark(id)
			}
			est := c.Count()
			assert.LessOrEqual(t, math.Abs(float64(n)-float64(est)), math.Ceil(float64(n)*0.01))
		})
	}
}

func TestSerialize(t *testing.T) {
	t.Parallel()

	c := counter.New(counter.DefaultCap)
	for _, id := range stableRandomUUIDs(20) {
		c.Mark(id)
	}
	assert.EqualValues(t, 20, c.Count())

	data, err := c.ToBinary()
	require.NoError(t, err)

	c2, err := counter.FromBinary(data)
	require.NoError(t, err)

	assert.EqualValues(t, 20, c2.Count())
}

func TestReset(t *testing.T) {
	t.Parallel()

	c := counter.New(counter.DefaultCap)
	for _, id := range stableRandomUUIDs(20) {
		c.Mark(id)
	}
	assert.EqualValues(t, 20, c.Count())
	c.Reset()
	assert.EqualValues(t, 0, c.Count())
}
