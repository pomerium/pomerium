package analytics

import (
	"time"

	"github.com/pomerium/pomerium/pkg/counter"
)

const (
	activeUsersCap = 10_000
)

// IntervalResetFunc is a function that determines if a counter should be reset
type IntervalResetFunc func(lastReset time.Time, now time.Time) bool

// ResetMonthlyUTC resets the counter on a monthly interval
func ResetMonthlyUTC(lastReset time.Time, now time.Time) bool {
	lastResetUTC := lastReset.UTC()
	nowUTC := now.UTC()
	return lastResetUTC.Year() != nowUTC.Year() ||
		lastResetUTC.Month() != nowUTC.Month()
}

// ResetDailyUTC resets the counter on a daily interval
func ResetDailyUTC(lastReset time.Time, now time.Time) bool {
	lastResetUTC := lastReset.UTC()
	nowUTC := now.UTC()
	return lastResetUTC.Year() != nowUTC.Year() ||
		lastResetUTC.Month() != nowUTC.Month() ||
		lastResetUTC.Day() != nowUTC.Day()
}

// ActiveUsersCounter is a counter that resets on a given interval
type ActiveUsersCounter struct {
	*counter.Counter
	lastReset  time.Time
	needsReset IntervalResetFunc
}

// NewActiveUsersCounter creates a new active users counter
func NewActiveUsersCounter(needsReset IntervalResetFunc, now time.Time) *ActiveUsersCounter {
	return &ActiveUsersCounter{
		Counter:    counter.New(activeUsersCap),
		lastReset:  now,
		needsReset: needsReset,
	}
}

// LoadActiveUsersCounter loads an active users counter from a binary state
func LoadActiveUsersCounter(state []byte, lastReset time.Time, resetFn IntervalResetFunc) (*ActiveUsersCounter, error) {
	c, err := counter.FromBinary(state)
	if err != nil {
		return nil, err
	}
	return &ActiveUsersCounter{
		Counter:    c,
		lastReset:  lastReset,
		needsReset: resetFn,
	}, nil
}

// Update updates the counter with the current users
func (c *ActiveUsersCounter) Update(users []string, now time.Time) (wasReset bool) {
	if c.needsReset(c.lastReset, now) {
		c.Counter.Reset()
		c.lastReset = now
		wasReset = true
	}
	for _, user := range users {
		c.Mark(user)
	}
	return wasReset
}

// GetLastReset returns the last time the counter was reset
func (c *ActiveUsersCounter) GetLastReset() time.Time {
	return c.lastReset
}
