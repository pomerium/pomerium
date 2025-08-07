package iterutil_test

import (
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
