package circuit // import "github.com/pomerium/pomerium/internal/circuit"

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/benbjohnson/clock"
)

var errFailed = errors.New("failed")

func fail() (interface{}, error) {
	return nil, errFailed
}

func succeed() (interface{}, error) {
	return nil, nil
}

func TestCircuitBreaker(t *testing.T) {
	mock := clock.NewMock()
	threshold := 3
	timeout := time.Duration(2) * time.Second
	trip := func(c Counts) bool { return c.ConsecutiveFailures > threshold }
	reset := func(c Counts) bool { return c.ConsecutiveSuccesses > threshold }
	backoff := func(c Counts) time.Duration { return timeout }
	stateChange := func(p, c State) { t.Logf("state change from %s to %s\n", p, c) }
	cb := NewBreaker(&Options{
		TestClock:           mock,
		ShouldTripFunc:      trip,
		ShouldResetFunc:     reset,
		BackoffDurationFunc: backoff,
		OnStateChange:       stateChange,
	})
	state, _ := cb.currentState()
	if state != StateClosed {
		t.Fatalf("expected state to start %s, got %s", StateClosed, state)
	}

	for i := 0; i <= threshold; i++ {
		_, err := cb.Call(fail)
		if err == nil {
			t.Fatalf("expected to error, got nil")
		}
		state, _ := cb.currentState()
		t.Logf("iteration %#v", i)
		if i == threshold {
			// we expect this to be the case to trip the circuit
			if state != StateOpen {
				t.Fatalf("expected state to be %s, got %s", StateOpen, state)
			}
		} else if state != StateClosed {
			// this is a normal failure case
			t.Fatalf("expected state to be %s, got %s", StateClosed, state)
		}
	}

	_, err := cb.Call(fail)
	switch err.(type) {
	case *ErrOpenState:
		// this is the expected case
		break
	default:
		t.Errorf("%#v", cb.counts)
		t.Fatalf("expected to get open state failure, got %s", err)
	}

	// we advance time by the timeout and a hair
	mock.Add(timeout + time.Duration(1)*time.Millisecond)
	state, _ = cb.currentState()
	if state != StateHalfOpen {
		t.Fatalf("expected state to be %s, got %s", StateHalfOpen, state)
	}

	for i := 0; i <= threshold; i++ {
		_, err := cb.Call(succeed)
		if err != nil {
			t.Fatalf("expected to get no error, got %s", err)
		}
		state, _ := cb.currentState()
		t.Logf("iteration %#v", i)
		if i == threshold {
			// we expect this to be the case that ressets the circuit
			if state != StateClosed {
				t.Fatalf("expected state to be %s, got %s", StateClosed, state)
			}
		} else if state != StateHalfOpen {
			t.Fatalf("expected state to be %s, got %s", StateHalfOpen, state)
		}
	}

	state, _ = cb.currentState()
	if state != StateClosed {
		t.Fatalf("expected state to be %s, got %s", StateClosed, state)
	}
}

func TestExponentialBackOffFunc(t *testing.T) {
	baseTimeout := time.Duration(1) * time.Millisecond
	// Note Expected is an upper range case
	cases := []struct {
		FailureCount int
		Expected     time.Duration
	}{
		{
			FailureCount: 0,
			Expected:     time.Duration(1) * time.Millisecond,
		},
		{
			FailureCount: 1,
			Expected:     time.Duration(2) * time.Millisecond,
		},
		{
			FailureCount: 2,
			Expected:     time.Duration(4) * time.Millisecond,
		},
		{
			FailureCount: 3,
			Expected:     time.Duration(8) * time.Millisecond,
		},
		{
			FailureCount: 4,
			Expected:     time.Duration(16) * time.Millisecond,
		},
		{
			FailureCount: 5,
			Expected:     time.Duration(32) * time.Millisecond,
		},
		{
			FailureCount: 6,
			Expected:     time.Duration(64) * time.Millisecond,
		},
		{
			FailureCount: 7,
			Expected:     time.Duration(128) * time.Millisecond,
		},
		{
			FailureCount: 8,
			Expected:     time.Duration(256) * time.Millisecond,
		},
		{
			FailureCount: 9,
			Expected:     time.Duration(512) * time.Millisecond,
		},
		{
			FailureCount: 10,
			Expected:     time.Duration(1024) * time.Millisecond,
		},
	}

	f := ExponentialBackoffDuration(time.Duration(1)*time.Hour, baseTimeout)
	for _, tc := range cases {
		got := f(Counts{ConsecutiveFailures: tc.FailureCount})
		t.Logf("got backoff %#v", got)
		if got > tc.Expected {
			t.Errorf("got %#v but expected less than %#v", got, tc.Expected)
		}
	}
}

func TestCircuitBreakerClosedParallel(t *testing.T) {
	cb := NewBreaker(nil)
	numReqs := 10000
	wg := &sync.WaitGroup{}
	routine := func(wg *sync.WaitGroup) {
		for i := 0; i < numReqs; i++ {
			cb.Call(succeed)
		}
		wg.Done()
	}

	numRoutines := 10
	for i := 0; i < numRoutines; i++ {
		wg.Add(1)
		go routine(wg)
	}

	total := numReqs * numRoutines

	wg.Wait()

	if cb.counts.ConsecutiveSuccesses != total {
		t.Fatalf("expected to get total requests %d, got %d", total, cb.counts.ConsecutiveSuccesses)
	}
}
