package healthv2

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func snapshot(checkers ...CheckerStatus) Snapshot {
	return Snapshot{Checkers: checkers}
}

func TestSnapshotProbes(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name                        string
		snap                        Snapshot
		initialized, ready, healthy bool
		keys                        []string
	}{
		{
			name: "empty",
			snap: Snapshot{},
		},
		{
			name:        "ok",
			snap:        snapshot(running(ServiceProxy, "c")),
			initialized: true, ready: true, healthy: true,
			keys: []string{"Proxy/c"},
		},
		{
			name:    "starting",
			snap:    snapshot(uninitialized(running("", "c"), "loading")),
			healthy: true,
			keys:    []string{"/c"},
		},
		{
			name:        "not_ready",
			snap:        snapshot(checkerStatus("", "c", fail("syncing"), pass(nil))),
			initialized: true, healthy: true,
			keys: []string{"/c"},
		},
		{
			name:        "unhealthy",
			snap:        snapshot(checkerStatus("", "c", pass(nil), fail("boom"))),
			initialized: true, ready: true,
			keys: []string{"/c"},
		},
		{
			name: "one_of_many",
			snap: snapshot(
				running(ServiceAuthorize, "b"),
				checkerStatus(ServiceAuthorize, "c", fail("syncing"), fail("boom")),
				running(ServiceProxy, "a"),
			),
			initialized: true,
			keys:        []string{"Authorize/b", "Authorize/c", "Proxy/a"},
		},
		{
			name: "info_ignored",
			snap: snapshot(checkerStatus("", "c",
				Condition{OK: true, Info: Info{Reason: "stale", Details: map[string]string{"role": "follower"}}},
				pass(map[string]string{"k": "v"}),
			)),
			initialized: true, ready: true, healthy: true,
			keys: []string{"/c"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.initialized, tc.snap.Initialized(), "initialized")
			assert.Equal(t, tc.ready, tc.snap.Ready(), "ready")
			assert.Equal(t, tc.healthy, tc.snap.Healthy(), "healthy")
			assert.Equal(t, tc.keys, tc.snap.Keys(), "keys")
		})
	}
}

func TestCheckerStatusState(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name       string
		status     CheckerStatus
		state      State
		reason     string
		hasFailure bool
	}{
		{
			name:   "ok",
			status: running("", "c"),
			state:  StateOK,
		},
		{
			name:   "starting",
			status: uninitialized(running("", "c"), "loading"),
			state:  StateStarting, reason: "loading", hasFailure: true,
		},
		{
			name:   "not_ready",
			status: checkerStatus("", "c", fail("syncing"), pass(nil)),
			state:  StateNotReady, reason: "syncing", hasFailure: true,
		},
		{
			name:   "unhealthy",
			status: checkerStatus("", "c", pass(nil), fail("boom")),
			state:  StateUnhealthy, reason: "boom", hasFailure: true,
		},
		{
			name:   "unhealthy_over_starting",
			status: uninitialized(checkerStatus("", "c", pass(nil), fail("boom")), "loading"),
			state:  StateUnhealthy, reason: "boom", hasFailure: true,
		},
		{
			name:   "unhealthy_over_not_ready",
			status: checkerStatus("", "c", fail("syncing"), fail("boom")),
			state:  StateUnhealthy, reason: "boom", hasFailure: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.state, tc.status.State())
			reason, hasFailure := tc.status.Reason()
			assert.Equal(t, tc.reason, reason)
			assert.Equal(t, tc.hasFailure, hasFailure)
		})
	}
}
