package slices

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMap(t *testing.T) {
	t.Parallel()

	in := []string{"one", "two", "three", "four"}

	assert.Equal(t, []string{"ONE", "TWO", "THREE", "FOUR"}, Map(in, strings.ToUpper))

	stringLen := func(s string) int { return len(s) }
	assert.Equal(t, []int{3, 3, 5, 4}, Map(in, stringLen))
}

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
