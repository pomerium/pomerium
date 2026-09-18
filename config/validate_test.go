package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateAgenticAddress(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		addr string
		ok   bool
	}{
		{"127.0.0.1:9300", true},
		{"127.0.0.2:9300", true},
		// A loopback name is not a literal, and the bind takes the address verbatim.
		{"localhost:9300", false},
		// Parses, passes IsLoopback, then fails to bind — reuseport is tcp4-only,
		// and that bind failure is fatal.
		{"[::1]:9300", false},
		{"0.0.0.0:9300", false},
		{"10.0.0.1:9300", false},
		{"127.0.0.1", false},
		{"127.0.0.1:0", false},
		{"", false},
	} {
		err := ValidateAgenticAddress(tc.addr)
		if tc.ok {
			assert.NoError(t, err, "%q must be accepted", tc.addr)
		} else {
			assert.Error(t, err, "%q must be rejected", tc.addr)
		}
	}
}
