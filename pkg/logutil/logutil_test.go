package logutil_test

import (
	"errors"
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

	t.Run("error", func(t *testing.T) {
		e := errors.New("test error")
		pr, pw := io.Pipe()
		pw.CloseWithError(e)

		cnt := 0
		for range logutil.IterateLines(pr) {
			cnt++
		}
		assert.Equal(t, 0, cnt)
	})
}
