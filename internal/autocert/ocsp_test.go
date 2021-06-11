package autocert

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOcspCache(t *testing.T) {
	c, err := newOCSPCache(10)
	require.NoError(t, err)

	cases := []struct {
		data      []byte
		isUpdated bool
	}{
		{nil, false},
		{nil, false},
		{[]byte("a"), true},
		{[]byte("a"), false},
		{[]byte("b"), true},
		{[]byte("b"), false},
		{nil, true},
		{nil, false},
	}

	for i, tc := range cases {
		assert.Equal(t, tc.isUpdated, c.updated("key", tc.data), "#%d: %v", i, tc)
	}
}
