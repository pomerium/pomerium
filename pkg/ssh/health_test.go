package ssh

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStreamManagerHealth(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name           string
		sshAddr        string
		running        bool
		synced         bool
		ready, healthy bool
	}{
		{"disabled", "", false, false, true, true},
		{"not_running", ":2200", false, false, false, false},
		{"syncing", ":2200", true, false, false, true},
		{"synced", ":2200", true, true, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			sm := &StreamManager{
				initialSessionSyncDone:        tc.synced,
				initialSessionBindingSyncDone: tc.synced,
			}
			sm.running.Store(tc.running)
			sm.sshEnabled.Store(tc.sshAddr != "")

			ready, _ := sm.Ready(t.Context())
			assert.Equal(t, tc.ready, ready)
			healthy, _ := sm.Healthy(t.Context())
			assert.Equal(t, tc.healthy, healthy)
		})
	}
}
