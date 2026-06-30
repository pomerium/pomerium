package logutil_test

import (
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/pkg/logutil"
)

func TestIterateLines(t *testing.T) {
	t.Parallel()

	result := slices.Collect(logutil.IterateLines(io.NopCloser(strings.NewReader("a\nb\r\nc"))))
	assert.Equal(t, []string{"a", "b", "c"}, result)
}
