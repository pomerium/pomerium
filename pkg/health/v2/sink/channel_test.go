package sink

import (
	"testing"

	"github.com/stretchr/testify/assert"

	healthv2 "github.com/pomerium/pomerium/pkg/health/v2"
	"github.com/pomerium/pomerium/pkg/health/v2/check"
)

func TestChannel(t *testing.T) {
	t.Parallel()

	signaled := func(c <-chan struct{}) bool {
		select {
		case _, ok := <-c:
			return ok
		default:
			return false
		}
	}

	sink := NewChannel()
	for _, step := range []struct {
		name                     string
		snap                     healthv2.Snapshot
		wantReady, wantTerminate bool
	}{
		{"starting", snapshotOf(running("a"), check.Result{Name: "b"}), false, false},
		{"error is not ready", snapshotOf(running("a"), failing("b", check.StatusRunning, "x")), false, false},
		{"ready", snapshotOf(running("a"), running("b")), true, false},
		{"ready only once", snapshotOf(running("a"), running("b", check.Attr{Key: "k", Value: "v"})), false, false},
		{"partially terminating", snapshotOf(terminating("a"), running("b")), false, false},
		{"terminating", snapshotOf(terminating("a"), terminating("b")), false, true},
		{"terminating only once", snapshotOf(terminating("a")), false, false},
	} {
		sink.Notify(step.snap)
		assert.Equal(t, step.wantReady, signaled(sink.OnReady()), step.name)
		assert.Equal(t, step.wantTerminate, signaled(sink.OnTerminating()), step.name)
	}

	sink.Close()
	sink.Close()
	sink.Notify(snapshotOf(running("a")))
}
