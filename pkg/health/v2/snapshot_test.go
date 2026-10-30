package healthv2

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/pkg/health/v2/check"
)

func TestSnapshotProbes(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name                 string
		snap                 Snapshot
		started, ready, live bool
	}{
		{
			name: "unknown",
			snap: Snapshot{Configured: true, Checkers: []CheckerStatus{
				checkerStatus("", "c", check.Result{Name: "a"}),
			}},
		},
		{
			name: "unknown with error",
			snap: Snapshot{Configured: true, Checkers: []CheckerStatus{
				checkerStatus("", "c", failing("a", check.StatusUnknown, "boom")),
			}},
		},
		{
			name: "running",
			snap: Snapshot{Configured: true, Checkers: []CheckerStatus{
				checkerStatus("", "c", running("a")),
			}},
			started: true, ready: true, live: true,
		},
		{
			name: "running with error",
			snap: Snapshot{Configured: true, Checkers: []CheckerStatus{
				checkerStatus("", "c", failing("a", check.StatusRunning, "boom")),
			}},
			started: true,
		},
		{
			name: "terminating",
			snap: Snapshot{Configured: true, Checkers: []CheckerStatus{
				checkerStatus("", "c", terminating("a")),
			}},
			started: true, live: true,
		},
		{
			name: "terminating with error",
			snap: Snapshot{Configured: true, Checkers: []CheckerStatus{
				checkerStatus("", "c", failing("a", check.StatusTerminating, "boom")),
			}},
			started: true,
		},
		{
			name: "one of many failing",
			snap: Snapshot{Configured: true, Checkers: []CheckerStatus{
				checkerStatus("", "c1", running("a"), running("b")),
				checkerStatus("", "c2", failing("c", check.StatusRunning, "boom")),
			}},
			started: true,
		},
		{
			name: "one check not reported",
			snap: Snapshot{Configured: true, Checkers: []CheckerStatus{
				checkerStatus("", "c1", running("a")),
				checkerStatus("", "c2", check.Result{Name: "b"}),
			}},
		},
		{
			name: "not configured",
			snap: Snapshot{},
		},
		{
			name:    "configured without checkers",
			snap:    Snapshot{Configured: true},
			started: true, ready: true, live: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.started, tc.snap.Started(), "started")
			assert.Equal(t, tc.ready, tc.snap.Ready(), "ready")
			assert.Equal(t, tc.live, tc.snap.Live(), "live")
		})
	}
}

func TestSnapshotRequired(t *testing.T) {
	t.Parallel()
	snap := Snapshot{Checkers: []CheckerStatus{
		checkerStatus("", "c1", running("b"), running("a")),
		checkerStatus("", "c2", check.Result{Name: "c"}),
	}}
	assert.Equal(t, []string{"a", "b", "c"}, snap.Required())
}
