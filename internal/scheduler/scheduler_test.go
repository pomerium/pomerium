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
	s.Add(tm2, "a")
	{
		tm, key := s.Next()
		assert.Equal(t, tm2, tm)
		assert.Equal(t, "a", key)
	}
	s.Add(tm1, "b")
	{
		tm, key := s.Next()
		assert.Equal(t, tm1, tm)
		assert.Equal(t, "b", key)
	}
	s.Remove("b")
	{
		tm, key := s.Next()
		assert.Equal(t, tm2, tm)
		assert.Equal(t, "a", key)
	}
	s.Remove("a")
	{
		tm, key := s.Next()
		assert.Equal(t, maxTime, tm)
		assert.Equal(t, "", key)
	}
}
