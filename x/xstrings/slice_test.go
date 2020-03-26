package xslice

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCommaSlice(t *testing.T) {
	var (
		s       CommaSlice
		values  = []string{"a", "b"}
		cvalues = strings.Join(values, ",")
	)
	require.Equal(t, nil, s.Set(cvalues), "should set once")
	require.Equal(t, values, []string(s))
	require.Equal(t, errAlreadySet, s.Set(cvalues), "should not set more than once")
}
