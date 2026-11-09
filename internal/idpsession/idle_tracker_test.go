package idpsession_test

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/internal/idpsession"
)

func TestIdleTracker(t *testing.T) {
	start := time.Date(2026, time.September, 28, 12, 0, 0, 0, time.UTC)

	t.Run("returns and consumes due sessions", func(t *testing.T) {
		tracker := idpsession.NewIdleTracker()
		tracker.Set("later", start.Add(time.Minute))
		tracker.Set("same-b", start)
		tracker.Set("same-a", start)

		assert.Empty(t, processIdle(t, tracker, start.Add(-time.Nanosecond)))
		assert.Equal(t, []string{"same-a", "same-b"}, processIdle(t, tracker, start))
		assert.Empty(t, processIdle(t, tracker, start))
		assert.Equal(t, []string{"later"}, processIdle(t, tracker, start.Add(time.Minute)))
	})

	t.Run("set preserves an existing deadline", func(t *testing.T) {
		tracker := idpsession.NewIdleTracker()
		tracker.Set("session", start)
		tracker.Set("session", start.Add(time.Hour))

		assert.Equal(t, []string{"session"}, processIdle(t, tracker, start))
		assert.Empty(t, processIdle(t, tracker, start.Add(time.Hour)))
	})

	t.Run("clear permits a new deadline", func(t *testing.T) {
		tracker := idpsession.NewIdleTracker()
		tracker.Set("session", start)
		tracker.Clear("session")
		tracker.Set("session", start.Add(time.Hour))

		require.Empty(t, processIdle(t, tracker, start))
		assert.Equal(t, []string{"session"}, processIdle(t, tracker, start.Add(time.Hour)))
	})

	t.Run("clear and reset remove deadlines", func(t *testing.T) {
		tracker := idpsession.NewIdleTracker()
		tracker.Set("cleared", start)
		tracker.Clear("cleared")
		tracker.Set("reset", start)
		tracker.Reset()

		assert.Empty(t, processIdle(t, tracker, start))
	})

	t.Run("failed processing retains deadlines", func(t *testing.T) {
		tracker := idpsession.NewIdleTracker()
		tracker.Set("session", start)
		wantErr := errors.New("delete session")

		require.ErrorIs(t, tracker.ProcessDue(start, func([]string) error {
			return wantErr
		}), wantErr)
		assert.Equal(t, []string{"session"}, processIdle(t, tracker, start))
	})
}

func processIdle(t *testing.T, tracker idpsession.IdleTracker, at time.Time) []string {
	t.Helper()
	var ids []string
	require.NoError(t, tracker.ProcessDue(at, func(due []string) error {
		ids = due
		return nil
	}))
	return ids
}
