package config

import (
	"math"
	"testing"
	"time"

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

func TestAgenticRunIdleTimeoutBounds(t *testing.T) {
	t.Parallel()

	newOptions := func(d time.Duration) *Options {
		o := NewDefaultOptions()
		o.AgenticRunIdleTimeout = d
		return o
	}

	// The record TTL is the idle timeout plus a day of slack, so a value within a
	// day of the maximum duration overflows into a negative TTL. Rejecting it
	// here is what keeps GetAgenticRunRecordTTL total.
	for _, tc := range []struct {
		name string
		d    time.Duration
		ok   bool
	}{
		{"zero falls back to the default", 0, true},
		{"an ordinary value", 48 * time.Hour, true},
		{"the largest non-overflowing value", math.MaxInt64 - agenticRunRecordTTLSlack, true},
		{"negative", -time.Second, false},
		{"one tick past the overflow boundary", math.MaxInt64 - agenticRunRecordTTLSlack + 1, false},
		{"the maximum duration", math.MaxInt64, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := newOptions(tc.d)
			err := o.Validate()
			if !tc.ok {
				assert.Error(t, err, "%s must be rejected", tc.d)
				return
			}
			assert.NoError(t, err, "%s must be accepted", tc.d)
			assert.Positive(t, o.GetAgenticRunRecordTTL(),
				"an accepted idle timeout must yield a positive record TTL")
		})
	}
}
