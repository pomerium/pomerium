package slices

import (
	"fmt"
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

func TestAssociate(t *testing.T) {
	t.Parallel()

	type foo struct {
		baz string
		bar int
	}
	transform := func(f *foo) (string, int) {
		return f.baz, f.bar
	}
	testCases := []struct {
		in   []*foo
		want map[string]int
	}{
		{
			in:   []*foo{{baz: "apple", bar: 1}},
			want: map[string]int{"apple": 1},
		},
		{
			in:   []*foo{{baz: "apple", bar: 1}, {baz: "banana", bar: 2}},
			want: map[string]int{"apple": 1, "banana": 2},
		},
		{
			in:   []*foo{{baz: "apple", bar: 1}, {baz: "apple", bar: 2}},
			want: map[string]int{"apple": 2},
		},
	}
	for i, tc := range testCases {
		t.Run(fmt.Sprintf("test_%d", i), func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, Associate(tc.in, transform))
		})
	}
}

func TestAssociateI(t *testing.T) {
	t.Parallel()

	transform := func(s string, i int) (int, string) {
		return i % 2, s
	}
	testCases := []struct {
		in   []string
		want map[int]string
	}{
		{
			in:   []string{"zero"},
			want: map[int]string{0: "zero"},
		},
		{
			in:   []string{"zero", "one"},
			want: map[int]string{0: "zero", 1: "one"},
		},
		{
			in:   []string{"two", "one", "zero"},
			want: map[int]string{0: "zero", 1: "one"},
		},
	}
	for i, tc := range testCases {
		t.Run(fmt.Sprintf("test_%d", i), func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, AssociateI(tc.in, transform))
		})
	}
}
