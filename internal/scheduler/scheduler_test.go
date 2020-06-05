package scheduler

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestScheduler(t *testing.T) {
	tm1 := time.Date(2020, 6, 5, 12, 0, 0, 0, time.UTC)
	tm2 := tm1.Add(time.Minute)

	s := New()
	s.Add(tm2, "a", "b")
	assert.Equal(t, tm2, s.Next())
	s.Add(tm1, "x", "y")
	assert.Equal(t, tm1, s.Next())
	s.Remove("x")
	assert.Equal(t, tm2, s.Next())
	s.Remove("a")
	assert.Equal(t, maxTime, s.Next())
}
