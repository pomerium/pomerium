package sink

import (
	"testing"

	"github.com/stretchr/testify/assert"

	healthv2 "github.com/pomerium/pomerium/pkg/health/v2"
)

func TestChannel(t *testing.T) {
	t.Parallel()

	signaled := func(c <-chan struct{}) bool {
		select {
		case <-c:
			return true
		default:
			return false
		}
	}

	sink := NewChannel()
	for _, step := range []struct {
		name      string
		snap      healthv2.Snapshot
		wantReady bool
	}{
		{"empty", healthv2.Snapshot{}, false},
		{"starting", snapshotOf(running("a"), uninitialized(running("b"), "loading")), false},
		{"not_ready", snapshotOf(running("a"), checkerStatus("b", fail("syncing"), pass(nil))), false},
		{"ready", snapshotOf(running("a"), running("b")), true},
		{"ready_once", snapshotOf(running("a"), checkerStatus("b", pass(map[string]string{"k": "v"}), pass(nil))), false},
	} {
		sink.Notify(step.snap)
		assert.Equal(t, step.wantReady, signaled(sink.OnReady()), step.name)
	}
}
