package idpsession

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/pkg/grpc/idpsession"
)

func TestIdentityIndex(t *testing.T) {
	t.Run("indexes copies of IDP sessions", func(t *testing.T) {
		index, queue, idle := newTestIdentityIndex()
		at := time.Unix(100, 0)
		session := &idpsession.IDPSession{Id: "session", Sid: new("sid-a"), UserId: "user-a"}

		index.PutIDPSession(session, at)
		session.UserId = "mutated"
		stored, ok := index.IDPSession("session")
		require.True(t, ok)
		assert.Equal(t, "user-a", stored.GetUserId())
		stored.UserId = "also-mutated"
		byUser := index.IDPSessionsByUser("user-a")
		require.Len(t, byUser, 1)
		assert.Equal(t, "user-a", byUser[0].GetUserId())
		assert.Equal(t, []string{"session"}, processIdle(t, idle, at.Add(idpSessionIdleWindow)))
		assert.Equal(t, []ChangeSet{{
			At:            at,
			RecordID:      "session",
			RecordTypeURL: idpSessionTypeURL,
			changeType:    changePropagate,
		}}, processChanges(t, queue, at))

		index.PutIDPSession(&idpsession.IDPSession{
			Id: "session", Sid: new("sid-b"), UserId: "user-b",
		}, at)
		assert.Empty(t, index.IDPSessionsBySID("sid-a"))
		assert.Empty(t, index.IDPSessionsByUser("user-a"))
		bySID := index.IDPSessionsBySID("sid-b")
		byUser = index.IDPSessionsByUser("user-b")
		require.Len(t, bySID, 1)
		require.Len(t, byUser, 1)
		assert.Equal(t, "session", bySID[0].GetId())
		assert.Equal(t, "session", byUser[0].GetId())
	})

	t.Run("updates", func(t *testing.T) {
		index, queue, idle := newTestIdentityIndex()
		at := time.Unix(200, 0)
		index.PutIDPSession(&idpsession.IDPSession{Id: "session", UserId: "user"}, at)
		processChanges(t, queue, at)

		index.PutBinding(&idpsession.Binding{
			Id: "binding", IdpSessionId: "session", TypeUrl: "type.example/Dependent",
		}, at)
		assert.Empty(t, processIdle(t, idle, at.Add(idpSessionIdleWindow)))
		assert.Equal(t, []ChangeSet{{
			At: at, RecordID: "binding", RecordTypeURL: bindingTypeURL, changeType: changePropagate,
		}}, processChanges(t, queue, at))

		deletedAt := at.Add(time.Minute)
		index.DeleteBinding("binding", deletedAt)
		assert.Equal(t, []string{"session"}, processIdle(t, idle, deletedAt.Add(idpSessionIdleWindow)))
		assert.Equal(t, []ChangeSet{{
			At: deletedAt, RecordID: "binding", RecordTypeURL: bindingTypeURL, changeType: changeRevoke,
		}}, processChanges(t, queue, deletedAt))
	})

	t.Run("delete", func(t *testing.T) {
		index, queue, idle := newTestIdentityIndex()
		at := time.Unix(400, 0)
		index.PutIDPSession(&idpsession.IDPSession{
			Id: "session", Sid: new("sid"), UserId: "user",
		}, at)
		index.PutBinding(&idpsession.Binding{Id: "b2", IdpSessionId: "session"}, at)
		index.PutBinding(&idpsession.Binding{Id: "b1", IdpSessionId: "session"}, at)
		processChanges(t, queue, at)

		deletedAt := at.Add(time.Minute)
		index.DeleteIDPSession("session", deletedAt)
		_, ok := index.IDPSession("session")
		assert.False(t, ok)
		assert.Empty(t, index.IDPSessionsBySID("sid"))
		assert.Empty(t, index.IDPSessionsByUser("user"))
		assert.Empty(t, processIdle(t, idle, deletedAt.Add(idpSessionIdleWindow)))

		changes := processChanges(t, queue, deletedAt)
		require.Len(t, changes, 2)
		assert.ElementsMatch(t, []string{"b1", "b2"}, []string{changes[0].RecordID, changes[1].RecordID})
		assert.Equal(t, changeRevoke, changes[0].changeType)
		assert.Equal(t, changeRevoke, changes[1].changeType)
	})

	t.Run("reset", func(t *testing.T) {
		index, queue, idle := newTestIdentityIndex()
		at := time.Unix(500, 0)
		index.PutIDPSession(&idpsession.IDPSession{Id: "session", UserId: "user"}, at)

		index.Reset()
		_, ok := index.IDPSession("session")
		assert.False(t, ok)
		assert.Empty(t, processChanges(t, queue, at))
		assert.Empty(t, processIdle(t, idle, at.Add(idpSessionIdleWindow)))
	})
}

func newTestIdentityIndex() (IdentityIndex, ChangeQueue, IdleTracker) {
	queue := NewChangeQueue()
	idle := NewIdleTracker()
	return NewIdentityIndex(queue, idle), queue, idle
}

func processChanges(t *testing.T, queue ChangeQueue, at time.Time) []ChangeSet {
	t.Helper()
	var changes []ChangeSet
	require.NoError(t, queue.ProcessDue(at, func(due []ChangeSet) error {
		changes = due
		return nil
	}))
	return changes
}

func processIdle(t *testing.T, idle IdleTracker, at time.Time) []string {
	t.Helper()
	var ids []string
	require.NoError(t, idle.ProcessDue(at, func(due []string) error {
		ids = due
		return nil
	}))
	return ids
}
