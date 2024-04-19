package manager

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestUpdateUserInfoScheduler(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	var calls []time.Time

	ctx := context.Background()
	userUpdateInfoInterval := 100 * time.Millisecond
	uuis := newUpdateUserInfoScheduler(ctx, userUpdateInfoInterval, func(ctx context.Context, userID string) {
		mu.Lock()
		calls = append(calls, time.Now())
		mu.Unlock()
	}, "U1")
	t.Cleanup(uuis.Stop)

	// should eventually trigger
	assert.Eventually(t, func() bool {
		mu.Lock()
		n := len(calls)
		mu.Unlock()
		return n == 1
	}, 3*userUpdateInfoInterval, userUpdateInfoInterval/10, "should trigger once")

	uuis.Reset()
	uuis.Reset()
	uuis.Reset()

	assert.Eventually(t, func() bool {
		mu.Lock()
		n := len(calls)
		mu.Unlock()
		return n == 2
	}, 3*userUpdateInfoInterval, userUpdateInfoInterval/10, "should trigger once after multiple resets")

	mu.Lock()
	var diff time.Duration
	if len(calls) >= 2 {
		diff = calls[len(calls)-1].Sub(calls[len(calls)-2])
	}
	mu.Unlock()

	assert.GreaterOrEqual(t, diff, userUpdateInfoInterval, "delay should exceed interval")
}
