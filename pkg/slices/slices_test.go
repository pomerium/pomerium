package slices

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReverse(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		in     []int
		expect []int
	}{
		{in: []int{1, 2, 3}, expect: []int{3, 2, 1}},
		{in: []int{1, 2}, expect: []int{2, 1}},
		{in: []int{1}, expect: []int{1}},
	} {
		s := make([]int, len(tc.in))
		copy(s, tc.in)
		Reverse(s)
		assert.Equal(t, tc.expect, s)
	}
}

func TestUniqueBy(t *testing.T) {
	t.Parallel()

	s := UniqueBy([]int{1, 2, 3, 4, 3, 1, 1, 4, 2}, func(i int) int { return i % 3 })
	assert.Equal(t, []int{1, 2, 3}, s)
}
