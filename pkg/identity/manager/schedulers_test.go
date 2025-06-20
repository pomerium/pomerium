package manager

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/pkg/grpc/session"
)

func TestRefreshSessionScheduler(t *testing.T) {
	t.Parallel()

	var calls safeSlice[time.Time]
	ctx := t.Context()
	sessionRefreshGracePeriod := time.Millisecond
	sessionRefreshCoolOffDuration := time.Millisecond
	rss := newRefreshSessionScheduler(
		ctx,
		time.Now,
		sessionRefreshGracePeriod,
		sessionRefreshCoolOffDuration,
		func(_ context.Context, _ string) {
			calls.Append(time.Now())
		},
		"S1",
	)
	t.Cleanup(rss.Stop)

	rss.Update(&session.Session{ExpiresAt: timestamppb.Now()})

	assert.Eventually(t, func() bool {
		return calls.Len() == 1
	}, 100*time.Millisecond, 10*time.Millisecond, "should trigger once")

	rss.Update(&session.Session{ExpiresAt: timestamppb.Now()})

	assert.Eventually(t, func() bool {
		return calls.Len() == 2
	}, 100*time.Millisecond, 10*time.Millisecond, "should trigger again")
}

func TestUpdateUserInfoScheduler(t *testing.T) {
	t.Parallel()

	var calls safeSlice[time.Time]

	ctx := t.Context()
	userUpdateInfoInterval := 100 * time.Millisecond
	uuis := newUpdateUserInfoScheduler(ctx, userUpdateInfoInterval, func(_ context.Context, _ string) {
		calls.Append(time.Now())
	}, "U1")
	t.Cleanup(uuis.Stop)

	// should eventually trigger
	assert.Eventually(t, func() bool {
		return calls.Len() == 1
	}, 3*userUpdateInfoInterval, userUpdateInfoInterval/10, "should trigger once")

	uuis.Reset()
	uuis.Reset()
	uuis.Reset()

	assert.Eventually(t, func() bool {
		return calls.Len() == 2
	}, 3*userUpdateInfoInterval, userUpdateInfoInterval/10, "should trigger once after multiple resets")

	var diff time.Duration
	if calls.Len() >= 2 {
		diff = calls.At(calls.Len() - 1).Sub(calls.At(calls.Len() - 2))
	}

	assert.GreaterOrEqual(t, diff, userUpdateInfoInterval, "delay should exceed interval")

	uuis.Reset()
	uuis.Stop()

	time.Sleep(3 * userUpdateInfoInterval)

	assert.Equal(t, 2, calls.Len(), "should not trigger again after stopping")
}

type safeSlice[T any] struct {
	mu       sync.Mutex
	elements []T
}

func (s *safeSlice[T]) Append(elements ...T) {
	s.mu.Lock()
	s.elements = append(s.elements, elements...)
	s.mu.Unlock()
}

func (s *safeSlice[T]) At(idx int) T {
	var el T
	s.mu.Lock()
	if idx >= 0 && idx < len(s.elements) {
		el = s.elements[idx]
	}
	s.mu.Unlock()
	return el
}

func (s *safeSlice[T]) Len() int {
	s.mu.Lock()
	n := len(s.elements)
	s.mu.Unlock()
	return n
}
