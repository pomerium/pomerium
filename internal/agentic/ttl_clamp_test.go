package agentic

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// Regression for the CreateRun TTL overflow: a large client-supplied ttl_seconds
// used to overflow the int64 nanosecond multiplication and wrap to a NEGATIVE
// duration, which passed the `ttlSeconds > 0` guard yet was not `> maxRunTTL`,
// so the 24h clamp was silently bypassed and the run got an ExpiresAt in the
// past. clampRunTTL must bound every input to (0, maxRunTTL].
func TestClampRunTTL(t *testing.T) {
	// 9.3e9 seconds * 1e9 ns/s = 9.3e18 ns, which exceeds math.MaxInt64
	// (~9.223e18) and would wrap negative if converted before clamping.
	const hugeTTLSeconds = 9_300_000_000

	cases := []struct {
		name    string
		seconds int64
		want    time.Duration
	}{
		{"zero uses default", 0, defaultRunTTL},
		{"negative uses default", -5, defaultRunTTL},
		{"in-range preserved", 600, 600 * time.Second},
		{"over cap clamped", int64(maxRunTTL/time.Second) + 1, maxRunTTL},
		{"overflowing input clamped, not wrapped", hugeTTLSeconds, maxRunTTL},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := clampRunTTL(tc.seconds)
			assert.Equal(t, tc.want, got)
			assert.Greater(t, got, time.Duration(0),
				"a run TTL must always be positive")
			assert.LessOrEqual(t, got, maxRunTTL,
				"a run TTL must never exceed maxRunTTL")
		})
	}
}
