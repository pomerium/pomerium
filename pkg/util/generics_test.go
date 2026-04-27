package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFromPtrOr(t *testing.T) {
	t.Parallel()
	is := assert.New(t)

	const fallbackStr = "fallback"
	str := "foo"
	ptrStr := &str

	const fallbackInt = -1
	i := 9
	ptrInt := &i

	is.Equal(str, FromPtrOr(ptrStr, fallbackStr))
	is.Equal(fallbackStr, FromPtrOr(nil, fallbackStr))
	is.Equal(i, FromPtrOr(ptrInt, fallbackInt))
	is.Equal(fallbackInt, FromPtrOr(nil, fallbackInt))
}
