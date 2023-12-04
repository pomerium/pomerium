package analytics_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/internal/zero/analytics"
)

func TestActiveUsers(t *testing.T) {
	t.Parallel()

	startTime := time.Now().UTC()

	// Create a new counter that resets on a daily interval
	c := analytics.NewActiveUsersCounter(analytics.ResetDailyUTC, startTime)

	wasReset := c.Update([]string{"user1", "user2"}, startTime.Add(time.Minute))
	assert.False(t, wasReset)
	assert.EqualValues(t, 2, c.Count())

	wasReset = c.Update([]string{"user1", "user2", "user3"}, startTime.Add(time.Minute*2))
	assert.False(t, wasReset)
	assert.EqualValues(t, 3, c.Count())

	// Update the counter with a new user after lapse
	wasReset = c.Update([]string{"user1", "user2", "user3", "user4"}, startTime.Add(time.Hour*25))
	assert.True(t, wasReset)
	assert.EqualValues(t, 4, c.Count())

	// Update the counter with a new user after lapse
	wasReset = c.Update([]string{"user4"}, startTime.Add(time.Hour*25*2))
	assert.True(t, wasReset)
	assert.EqualValues(t, 1, c.Count())
}
