package resolver

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

var scheduleNow = time.Unix(1_000_000, 0)

func constRand(v float64) func() float64 { return func() float64 { return v } }

func TestNextRefresh(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		ttl        time.Duration
		refresh    time.Duration
		renewable  bool
		rnd        float64
		wantOffset time.Duration
	}{
		{name: "flat poll, no jitter", ttl: 0, refresh: 5 * time.Minute, rnd: 0.5, wantOffset: 5 * time.Minute},
		{name: "non-renewable ttl", ttl: 100 * time.Second, refresh: 5 * time.Minute, rnd: 0.5, wantOffset: 90 * time.Second},
		{name: "renewable ttl", ttl: 100 * time.Second, refresh: 5 * time.Minute, renewable: true, rnd: 0.5, wantOffset: 66 * time.Second},
		{name: "jitter low", ttl: 0, refresh: 100 * time.Second, rnd: 0, wantOffset: 90 * time.Second},
		{name: "jitter high", ttl: 0, refresh: 100 * time.Second, rnd: 0.999999, wantOffset: 110 * time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := nextRefresh(scheduleNow, tt.ttl, tt.refresh, tt.renewable, constRand(tt.rnd))
			gotOffset := got.Sub(scheduleNow)
			// Allow a small rounding tolerance on the jittered cases.
			assert.InDelta(t, tt.wantOffset, gotOffset, float64(time.Second))
		})
	}
}

func TestNextRefreshJitterBounds(t *testing.T) {
	t.Parallel()

	base := 5 * time.Minute
	for _, rnd := range []float64{0, 0.1, 0.25, 0.5, 0.75, 0.9, 0.999999} {
		got := nextRefresh(scheduleNow, 0, base, false, constRand(rnd)).Sub(scheduleNow)
		assert.Greater(t, got, time.Duration(0), "never <= 0")
		assert.LessOrEqual(t, got, 2*base, "never > 2x base")
		assert.GreaterOrEqual(t, got, time.Duration(float64(base)*0.9)-time.Second)
		assert.LessOrEqual(t, got, time.Duration(float64(base)*1.1)+time.Second)
	}
}

func TestScheduleFloor(t *testing.T) {
	t.Parallel()

	// A sub-second interval is floored at minInterval regardless of jitter.
	for _, rnd := range []float64{0, 0.5, 0.999999} {
		got := nextRefresh(scheduleNow, 0, 100*time.Millisecond, false, constRand(rnd)).Sub(scheduleNow)
		assert.GreaterOrEqual(t, got, minInterval)
	}
}

func TestNextRefreshDeterministic(t *testing.T) {
	t.Parallel()

	a := nextRefresh(scheduleNow, 100*time.Second, 5*time.Minute, false, constRand(0.3))
	b := nextRefresh(scheduleNow, 100*time.Second, 5*time.Minute, false, constRand(0.3))
	assert.Equal(t, a, b)
}
