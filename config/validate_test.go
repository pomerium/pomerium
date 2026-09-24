package config

import (
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

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
