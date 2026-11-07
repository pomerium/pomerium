package idpsession_test

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/internal/idpsession"
)

func TestChangeQueue(t *testing.T) {
	now := time.Date(2026, time.September, 28, 12, 0, 0, 0, time.UTC)

	t.Run("processes due changes", func(t *testing.T) {
		dueFirst := changeSet(now.Add(-time.Minute), "first")
		dueLast := changeSet(now, "last")
		future := changeSet(now.Add(time.Minute), "future")
		queue := idpsession.NewChangeQueue()
		queue.Schedule(t.Context(), dueFirst, future, dueLast, dueLast)

		var batches [][]idpsession.ChangeSet
		process := func(changes []idpsession.ChangeSet) error {
			batches = append(batches, changes)
			return nil
		}
		require.NoError(t, queue.ProcessDue(now, process))
		require.Equal(t, [][]idpsession.ChangeSet{{dueLast, dueFirst}}, batches)
		require.NoError(t, queue.ProcessDue(now.Add(time.Minute), process))
		require.Equal(t, []idpsession.ChangeSet{future}, batches[1])
		require.NoError(t, queue.ProcessDue(now.Add(time.Hour), process))
		require.Len(t, batches, 2)
	})

	t.Run("retries a failed batch", func(t *testing.T) {
		want := changeSet(now, "record")
		queue := idpsession.NewChangeQueue()
		queue.Schedule(t.Context(), want)

		wantErr := errors.New("apply changes")
		require.ErrorIs(t, queue.ProcessDue(now, func(got []idpsession.ChangeSet) error {
			assert.Equal(t, []idpsession.ChangeSet{want}, got)
			return wantErr
		}), wantErr)

		var got []idpsession.ChangeSet
		require.NoError(t, queue.ProcessDue(now, func(changes []idpsession.ChangeSet) error {
			got = changes
			return nil
		}))
		require.Equal(t, []idpsession.ChangeSet{want}, got)
	})

	t.Run("callback can schedule a change", func(t *testing.T) {
		initial := changeSet(now, "initial")
		followUp := changeSet(now, "follow-up")
		queue := idpsession.NewChangeQueue()
		queue.Schedule(t.Context(), initial)

		require.NoError(t, queue.ProcessDue(now, func(got []idpsession.ChangeSet) error {
			require.Equal(t, []idpsession.ChangeSet{initial}, got)
			queue.Schedule(t.Context(), followUp)
			return nil
		}))
		require.NoError(t, queue.ProcessDue(now, func(got []idpsession.ChangeSet) error {
			require.Equal(t, []idpsession.ChangeSet{followUp}, got)
			return nil
		}))
	})

	t.Run("reset clears changes", func(t *testing.T) {
		queue := idpsession.NewChangeQueue()
		queue.Schedule(t.Context(), changeSet(now, "record"))
		queue.Reset()

		called := false
		require.NoError(t, queue.ProcessDue(now, func([]idpsession.ChangeSet) error {
			called = true
			return nil
		}))
		assert.False(t, called)
	})
}

func changeSet(at time.Time, id string) idpsession.ChangeSet {
	return idpsession.ChangeSet{
		At:            at,
		RecordID:      id,
		RecordTypeURL: "type.googleapis.com/test.Record",
	}
}
