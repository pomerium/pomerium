package iterutil_test

import (
	"cmp"
	"iter"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/pkg/iterutil"
)

func TestSkipLast(t *testing.T) {
	t.Parallel()

	assert.Equal(t, []int{1, 2, 3, 4, 5, 6, 7, 8, 9},
		slices.Collect(iterutil.SkipLast(slices.Values([]int{1, 2, 3, 4, 5, 6, 7, 8, 9}), 0)))
	assert.Equal(t, []int{1, 2, 3, 4, 5, 6},
		slices.Collect(iterutil.SkipLast(slices.Values([]int{1, 2, 3, 4, 5, 6, 7, 8, 9}), 3)))
}

func TestSortedIntersection(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		input  [][]int
		expect []int
	}{
		{
			input:  [][]int{},
			expect: nil,
		},
		{
			input:  [][]int{{1}, {1}},
			expect: []int{1},
		},
		{
			input:  [][]int{{1, 5, 11, 23, 99}, {1, 25, 99, 104}},
			expect: []int{1, 99},
		},
		{
			input:  [][]int{{1, 2, 3, 4, 5}, {1, 3, 5}, {2, 4, 5}, {5}},
			expect: []int{5},
		},
	} {
		seqs := make([]iter.Seq[int], len(tc.input))
		for i, input := range tc.input {
			seqs[i] = slices.Values(input)
		}
		actual := slices.Collect(iterutil.SortedIntersection(cmp.Compare[int], seqs...))
		assert.Equal(t, tc.expect, actual)
	}
}

func TestSortedUnion(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		input  [][]int
		expect []int
	}{
		{
			input:  [][]int{},
			expect: nil,
		},
		{
			input:  [][]int{{1}, {1}},
			expect: []int{1},
		},
		{
			input:  [][]int{{1, 5, 11, 23, 99}, {1, 25, 99, 104}},
			expect: []int{1, 5, 11, 23, 25, 99, 104},
		},
		{
			input:  [][]int{{1, 2, 3, 4, 5}, {1, 3, 5}, {2, 4, 5}, {5}},
			expect: []int{1, 2, 3, 4, 5},
		},
	} {
		seqs := make([]iter.Seq[int], len(tc.input))
		for i, input := range tc.input {
			seqs[i] = slices.Values(input)
		}
		actual := slices.Collect(iterutil.SortedUnion(cmp.Compare[int], seqs...))
		assert.Equal(t, tc.expect, actual)
	}
}
