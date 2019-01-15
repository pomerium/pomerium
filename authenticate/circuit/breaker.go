// Package circuit implements the Circuit Breaker pattern.
// https://docs.microsoft.com/en-us/azure/architecture/patterns/circuit-breaker
package circuit // import "github.com/pomerium/pomerium/internal/circuit"

import (
	"fmt"
	"math"
	"math/rand"
	"sync"
	"time"

	"github.com/benbjohnson/clock"
)

// State is a type that represents a state of Breaker.
type State int

// These constants are states of Breaker.
const (
	StateClosed State = iota
	StateHalfOpen
	StateOpen
)

type (
	// ShouldTripFunc is a function that takes in a Counts and returns true if the circuit breaker should be tripped.
	ShouldTripFunc func(Counts) bool
	// ShouldResetFunc is a function that takes in a Counts and returns true if the circuit breaker should be reset.
	ShouldResetFunc func(Counts) bool
	// BackoffDurationFunc is a function that takes in a Counts and returns the backoff duration
	BackoffDurationFunc func(Counts) time.Duration

	// StateChangeHook is a function that represents a state change.
	StateChangeHook func(prev, to State)
	// BackoffHook is a function that represents backoff.
	BackoffHook func(duration time.Duration, reset time.Time)
)

var (
	// DefaultShouldTripFunc is a default ShouldTripFunc.
	DefaultShouldTripFunc = func(counts Counts) bool {
		// Trip into Open after three consecutive failures
		return counts.ConsecutiveFailures >= 3
	}
	// DefaultShouldResetFunc is a default ShouldResetFunc.
	DefaultShouldResetFunc = func(counts Counts) bool {
		// Reset after three consecutive successes
		return counts.ConsecutiveSuccesses >= 3
	}
	// DefaultBackoffDurationFunc is an exponential backoff function
	DefaultBackoffDurationFunc = ExponentialBackoffDuration(time.Duration(100)*time.Second, time.Duration(500)*time.Millisecond)
)

// ErrOpenState is returned when the b state is open
type ErrOpenState struct{}

func (e *ErrOpenState) Error() string { return "circuit breaker is open" }

// ExponentialBackoffDuration returns a function that uses exponential backoff and full jitter
func ExponentialBackoffDuration(maxBackoff, baseTimeout time.Duration) func(Counts) time.Duration {
	return func(counts Counts) time.Duration {
		// Full Jitter from https://aws.amazon.com/blogs/architecture/exponential-backoff-and-jitter/
		// sleep = random_between(0, min(cap, base * 2 ** attempt))
		backoff := math.Min(float64(maxBackoff), float64(baseTimeout)*math.Exp2(float64(counts.ConsecutiveFailures)))
		jittered := rand.Float64() * backoff
		return time.Duration(jittered)
	}
}

// String implements stringer interface.
func (s State) String() string {
	switch s {
	case StateClosed:
		return "closed"
	case StateHalfOpen:
		return "half-open"
	case StateOpen:
		return "open"
	default:
		return fmt.Sprintf("unknown state: %d", s)
	}
}

// Counts holds the numbers of requests and their successes/failures.
type Counts struct {
	CurrentRequests      int
	ConsecutiveSuccesses int
	ConsecutiveFailures  int
}

func (c *Counts) onRequest() {
	c.CurrentRequests++
}

func (c *Counts) afterRequest() {
	c.CurrentRequests--
}

func (c *Counts) onSuccess() {
	c.ConsecutiveSuccesses++
	c.ConsecutiveFailures = 0
}

func (c *Counts) onFailure() {
	c.ConsecutiveFailures++
	c.ConsecutiveSuccesses = 0
}

func (c *Counts) clear() {
	c.ConsecutiveSuccesses = 0
	c.ConsecutiveFailures = 0
}

// Options configures Breaker:
//
// HalfOpenConcurrentRequests specifies how many concurrent requests to allow while
// the circuit is in the half-open state
//
// ShouldTripFunc specifies when the circuit should trip from the closed state to
// the open state. It takes a Counts struct and returns a bool.
//
// ShouldResetFunc specifies when the circuit should be reset from the half-open state
// to the closed state and allow all requests. It takes a Counts struct and returns a bool.
//
// BackoffDurationFunc specifies how long to set the backoff duration. It takes a
// counts struct and returns a time.Duration
//
// OnStateChange is called whenever the state of the Breaker changes.
//
// OnBackoff is called whenever a backoff is set with the backoff duration and reset time
//
// TestClock is used to mock the clock during tests
type Options struct {
	HalfOpenConcurrentRequests int

	ShouldTripFunc      ShouldTripFunc
	ShouldResetFunc     ShouldResetFunc
	BackoffDurationFunc BackoffDurationFunc

	// hooks
	OnStateChange StateChangeHook
	OnBackoff     BackoffHook

	// used in tests
	TestClock clock.Clock
}

// Breaker is a state machine to prevent sending requests that are likely to fail.
type Breaker struct {
	halfOpenRequests int

	shouldTripFunc      ShouldTripFunc
	shouldResetFunc     ShouldResetFunc
	backoffDurationFunc BackoffDurationFunc

	// hooks
	onStateChange StateChangeHook
	onBackoff     BackoffHook

	// used primarily for mocking tests
	clock clock.Clock

	mutex          sync.Mutex
	state          State
	counts         Counts
	backoffExpires time.Time
	generation     int
}

// NewBreaker returns a new Breaker configured with the given Settings.
func NewBreaker(opts *Options) *Breaker {
	b := new(Breaker)

	if opts == nil {
		opts = &Options{}
	}

	// set hooks
	b.onStateChange = opts.OnStateChange
	b.onBackoff = opts.OnBackoff

	b.halfOpenRequests = 1
	if opts.HalfOpenConcurrentRequests > 0 {
		b.halfOpenRequests = opts.HalfOpenConcurrentRequests
	}

	b.backoffDurationFunc = DefaultBackoffDurationFunc
	if opts.BackoffDurationFunc != nil {
		b.backoffDurationFunc = opts.BackoffDurationFunc
	}

	b.shouldTripFunc = DefaultShouldTripFunc
	if opts.ShouldTripFunc != nil {
		b.shouldTripFunc = opts.ShouldTripFunc
	}

	b.shouldResetFunc = DefaultShouldResetFunc
	if opts.ShouldResetFunc != nil {
		b.shouldResetFunc = opts.ShouldResetFunc
	}

	b.clock = clock.New()
	if opts.TestClock != nil {
		b.clock = opts.TestClock
	}

	b.setState(StateClosed)

	return b
}

// Call runs the given function if the Breaker allows the call.
// Call returns an error instantly if the Breaker rejects the request.
// Otherwise, Call returns the result of the request.
func (b *Breaker) Call(f func() (interface{}, error)) (interface{}, error) {
	generation, err := b.beforeRequest()
	if err != nil {
		return nil, err
	}

	result, err := f()
	b.afterRequest(err == nil, generation)
	return result, err
}

func (b *Breaker) beforeRequest() (int, error) {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	state, generation := b.currentState()

	switch state {
	case StateOpen:
		return generation, &ErrOpenState{}
	case StateHalfOpen:
		if b.counts.CurrentRequests >= b.halfOpenRequests {
			return generation, &ErrOpenState{}
		}
	}

	b.counts.onRequest()
	return generation, nil
}

func (b *Breaker) afterRequest(success bool, prevGeneration int) {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	b.counts.afterRequest()

	state, generation := b.currentState()
	if prevGeneration != generation {
		return
	}

	if success {
		b.onSuccess(state)
		return
	}

	b.onFailure(state)
}

func (b *Breaker) onSuccess(state State) {
	b.counts.onSuccess()
	switch state {
	case StateHalfOpen:
		if b.shouldResetFunc(b.counts) {
			b.setState(StateClosed)
			b.counts.clear()
		}
	}
}

func (b *Breaker) onFailure(state State) {
	b.counts.onFailure()

	switch state {
	case StateClosed:
		if b.shouldTripFunc(b.counts) {
			b.setState(StateOpen)
			b.counts.clear()
			b.setBackoff()
		}
	case StateOpen:
		b.setBackoff()
	case StateHalfOpen:
		b.setState(StateOpen)
		b.setBackoff()
	}
}

func (b *Breaker) setBackoff() {
	backoffDuration := b.backoffDurationFunc(b.counts)
	backoffExpires := b.clock.Now().Add(backoffDuration)
	b.backoffExpires = backoffExpires
	if b.onBackoff != nil {
		b.onBackoff(backoffDuration, backoffExpires)
	}
}

func (b *Breaker) currentState() (State, int) {
	switch b.state {
	case StateOpen:
		if b.clock.Now().After(b.backoffExpires) {
			b.setState(StateHalfOpen)
		}
	}
	return b.state, b.generation
}

func (b *Breaker) newGeneration() {
	b.generation++
}

func (b *Breaker) setState(state State) {
	if b.state == state {
		return
	}

	b.newGeneration()

	prev := b.state
	b.state = state

	if b.onStateChange != nil {
		b.onStateChange(prev, state)
	}
}
