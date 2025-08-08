package iterutil_test

import (
	"cmp"
	"iter"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/pkg/iterutil"
)

func TestChunk(t *testing.T) {
	t.Parallel()

	assert.Equal(t,
		[][]int{{1, 2}, {3, 4}, {5, 6}},
		slices.Collect(iterutil.Chunk(slices.Values([]int{1, 2, 3, 4, 5, 6}), 2)))
}

func TestFilter(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		input  []int
		fn     func(int) bool
		expect []int
	}{
		{
			input:  nil,
			fn:     func(i int) bool { return i%2 == 0 },
			expect: nil,
		},
		{
			input:  []int{1, 2, 3, 4, 5, 6},
			fn:     func(i int) bool { return i%2 == 0 },
			expect: []int{2, 4, 6},
		},
	} {
		actual := slices.Collect(iterutil.Filter(slices.Values(tc.input), tc.fn))
		assert.Equal(t, tc.expect, actual)
	}
}

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

func TestTake(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		input  []int
		n      int
		expect []int
	}{
		{
			input:  nil,
			n:      1,
			expect: nil,
		},
		{
			input:  []int{1, 2, 3},
			n:      1000,
			expect: []int{1, 2, 3},
		},
		{
			input:  []int{1, 2, 3, 4, 5},
			n:      3,
			expect: []int{1, 2, 3},
		},
	} {
		actual := slices.Collect(iterutil.Take(slices.Values(tc.input), tc.n))
		assert.Equal(t, tc.expect, actual)
	}
}

func TestZip(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		input1 []int
		input2 []int
		expect [][2]int
	}{
		{
			input1: nil,
			expect: nil,
		},
		{
			input1: []int{1, 2, 3},
			input2: nil,
			expect: nil,
		},
		{
			input1: nil,
			input2: []int{1, 2, 3},
			expect: nil,
		},
		{
			input1: []int{1, 2, 3},
			input2: []int{4, 5, 6},
			expect: [][2]int{{1, 4}, {2, 5}, {3, 6}},
		},
	} {
		seq := iterutil.Zip(slices.Values(tc.input1), slices.Values(tc.input2))
		var s [][2]int
		for k, v := range seq {
			s = append(s, [2]int{k, v})
		}
		assert.Equal(t, tc.expect, s)
	}
}
