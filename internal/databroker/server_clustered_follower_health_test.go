package databroker_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/pomerium/pomerium/internal/databroker"
	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/internal/testutil/healthtest"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpcutil"
	"github.com/pomerium/pomerium/pkg/health"
)

var errTestLeaderChanged = errors.New("test leader changed")

// flakyLeader wraps a databroker server and lets a test cancel every active
// Sync stream the way a leader does when it steps down and is elected again
// (clusteredServer cancels in-flight calls with `Unavailable: server changed`).
// While failing is set, new Sync streams fail immediately.
type flakyLeader struct {
	databroker.Server

	mu      sync.Mutex
	cancels map[int]context.CancelCauseFunc
	nextID  int
	failing bool
}

func newFlakyLeader(server databroker.Server) *flakyLeader {
	return &flakyLeader{Server: server, cancels: map[int]context.CancelCauseFunc{}}
}

// Break cancels all active Sync streams.
func (l *flakyLeader) Break() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, cancel := range l.cancels {
		cancel(errTestLeaderChanged)
	}
}

// SetFailing makes new Sync streams fail immediately (or work again).
func (l *flakyLeader) SetFailing(failing bool) {
	l.mu.Lock()
	l.failing = failing
	l.mu.Unlock()
}

type contextServerStream struct {
	grpc.ServerStreamingServer[databrokerpb.SyncResponse]
	ctx context.Context
}

func (s contextServerStream) Context() context.Context { return s.ctx }

func (l *flakyLeader) Sync(req *databrokerpb.SyncRequest, stream grpc.ServerStreamingServer[databrokerpb.SyncResponse]) error {
	l.mu.Lock()
	if l.failing {
		l.mu.Unlock()
		return status.Error(codes.Unavailable, "server changed")
	}
	ctx, cancel := context.WithCancelCause(stream.Context())
	id := l.nextID
	l.nextID++
	l.cancels[id] = cancel
	l.mu.Unlock()

	defer func() {
		l.mu.Lock()
		delete(l.cancels, id)
		l.mu.Unlock()
		cancel(nil)
	}()

	err := l.Server.Sync(req, contextServerStream{ServerStreamingServer: stream, ctx: ctx})
	if errors.Is(context.Cause(ctx), errTestLeaderChanged) {
		return status.Error(codes.Unavailable, "server changed")
	}
	return err
}

func newHealthTestFollower(t *testing.T, leader *flakyLeader) (databroker.Server, healthtest.HealthTester) {
	t.Helper()

	tracker := healthtest.NewTrackerForTest(t)
	leaderCC := testutil.NewGRPCServer(t, func(s *grpc.Server) {
		databrokerpb.RegisterDataBrokerServiceServer(s, leader)
	})
	local := databroker.NewBackendServer(noop.NewTracerProvider())
	follower := databroker.NewClusteredFollowerServer(noop.NewTracerProvider(), local, leaderCC,
		databroker.WithFollowerHealthAttrs(healthtest.HealhAttrTest(tracker.GetUUID())))
	t.Cleanup(follower.Stop)
	return local, tracker
}

// waitForLiveStream writes a record to the leader and waits for it to show up
// in the follower's local store, which proves the follower has a working Sync
// stream open.
func waitForLiveStream(t *testing.T, leader *flakyLeader, local databroker.Server, id string) {
	t.Helper()

	_, err := leader.Put(t.Context(), &databrokerpb.PutRequest{Records: []*databrokerpb.Record{
		databrokerpb.NewRecord(&session.Session{Id: id}),
	}})
	require.NoError(t, err)
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		_, err := local.Get(t.Context(), &databrokerpb.GetRequest{
			Type: grpcutil.GetTypeURL(new(session.Session)),
			Id:   id,
		})
		assert.NoError(c, err, "follower should sync %s", id)
	}, 10*time.Second, 20*time.Millisecond)
}

func TestClusteredFollowerServerHealth(t *testing.T) {
	t.Run("reports running again after each sync error", func(t *testing.T) {
		// A leader that steps down and is elected again cancels the followers'
		// Sync streams with `Unavailable: server changed`. The follower
		// reconnects and keeps syncing, so its health check must go green again
		// without waiting for a leader change.
		//
		// Run several cycles: the first error after startup is absorbed by the
		// follower's initial non-blocking sync, so a regression only shows from
		// the second error on.
		leader := newFlakyLeader(databroker.NewBackendServer(noop.NewTracerProvider()))
		local, tracker := newHealthTestFollower(t, leader)

		require.EventuallyWithT(t, func(c *assert.CollectT) {
			assert.NotEmpty(c, tracker.GetStatuses(health.DatabrokerCluster), "should be running after the first sync")
		}, 5*time.Second, 10*time.Millisecond)
		assert.Empty(t, tracker.GetErrors(health.DatabrokerCluster))

		for cycle := 1; cycle <= 3; cycle++ {
			waitForLiveStream(t, leader, local, fmt.Sprintf("before-%d", cycle))
			runningBefore := len(tracker.GetStatuses(health.DatabrokerCluster))
			errorsBefore := len(tracker.GetErrors(health.DatabrokerCluster))

			leader.Break()

			require.EventuallyWithT(t, func(c *assert.CollectT) {
				assert.Greater(c, len(tracker.GetErrors(health.DatabrokerCluster)), errorsBefore,
					"should report the sync error")
			}, 5*time.Second, 10*time.Millisecond)

			// the follower reconnects and keeps syncing...
			waitForLiveStream(t, leader, local, fmt.Sprintf("after-%d", cycle))

			// ...so the health check must be reported running again
			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				assert.Greater(c, len(tracker.GetStatuses(health.DatabrokerCluster)), runningBefore,
					"cycle %d: should report running again once the stream is re-established", cycle)
			}, 5*time.Second, 20*time.Millisecond)
		}
	})

	t.Run("does not report running while the leader keeps failing", func(t *testing.T) {
		leader := newFlakyLeader(databroker.NewBackendServer(noop.NewTracerProvider()))
		local, tracker := newHealthTestFollower(t, leader)

		require.EventuallyWithT(t, func(c *assert.CollectT) {
			assert.NotEmpty(c, tracker.GetStatuses(health.DatabrokerCluster))
		}, 5*time.Second, 10*time.Millisecond)

		// get past the first error, which the follower absorbs on its own
		waitForLiveStream(t, leader, local, "warmup-1")
		leader.Break()
		waitForLiveStream(t, leader, local, "warmup-2")

		leader.SetFailing(true)
		errorsBefore := len(tracker.GetErrors(health.DatabrokerCluster))
		leader.Break()

		require.EventuallyWithT(t, func(c *assert.CollectT) {
			assert.Greater(c, len(tracker.GetErrors(health.DatabrokerCluster)), errorsBefore)
		}, 5*time.Second, 10*time.Millisecond)

		// every reconnect fails straight away, so there must be no green
		// flashes while the leader is failing
		runningBefore := len(tracker.GetStatuses(health.DatabrokerCluster))
		time.Sleep(3 * time.Second)
		assert.Equal(t, runningBefore, len(tracker.GetStatuses(health.DatabrokerCluster)),
			"should not report running while every stream fails")

		// and it recovers once the leader works again
		leader.SetFailing(false)
		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			assert.Greater(c, len(tracker.GetStatuses(health.DatabrokerCluster)), runningBefore)
		}, 15*time.Second, 50*time.Millisecond, "should report running once the leader recovers")
	})
}
