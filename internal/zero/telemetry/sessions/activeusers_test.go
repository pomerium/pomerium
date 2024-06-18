package sessions_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/internal/zero/telemetry/sessions"
)

func TestActiveUsers(t *testing.T) {
	t.Parallel()

	startTime := time.Now().UTC()

	// Create a new counter that resets on a daily interval
	c := sessions.NewActiveUsersCounter(sessions.ResetDailyUTC, startTime)

	count, wasReset := c.Update([]string{"user1", "user2"}, startTime.Add(time.Minute))
	assert.False(t, wasReset)
	assert.EqualValues(t, 2, count)

	count, wasReset = c.Update([]string{"user1", "user2", "user3"}, startTime.Add(time.Minute*2))
	assert.False(t, wasReset)
	assert.EqualValues(t, 3, count)

	// Update the counter with a new user after lapse
	count, wasReset = c.Update([]string{"user1", "user2", "user3", "user4"}, startTime.Add(time.Hour*25))
	assert.True(t, wasReset)
	assert.EqualValues(t, 4, count)

	// Update the counter with a new user after lapse
	count, wasReset = c.Update([]string{"user4"}, startTime.Add(time.Hour*25*2))
	assert.True(t, wasReset)
	assert.EqualValues(t, 1, count)
}
