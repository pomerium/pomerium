package sink

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/pomerium/pomerium/internal/testutil"
	healthpb "github.com/pomerium/pomerium/pkg/grpc/health"
	"github.com/pomerium/pomerium/pkg/grpcutil"
	healthv2 "github.com/pomerium/pomerium/pkg/health/v2"
)

func readGoldenPb(t *testing.T, name string) *healthpb.HealthMessage {
	t.Helper()
	msg := &healthpb.HealthMessage{}
	require.NoError(t, protojson.Unmarshal(readGolden(t, name), msg))
	return msg
}

func TestSnapshotToPbGolden(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		golden string
		snap   healthv2.Snapshot
	}{
		{
			golden: "grpc_starting.json",
			snap: snapshotOf(
				running("h1"),
				checkerStatus("h2", pass(map[string]string{"foo": "bar"}), pass(map[string]string{"role": "leader"})),
				checkerStatus("h3", fail("syncing"), pass(nil)),
				uninitialized(checkerStatus("h4", pass(nil), pass(nil)), "loading"),
			),
		},
		{
			golden: "grpc_unhealthy.json",
			snap:   snapshotOf(running("h1"), checkerStatus("h2", pass(nil), fail("something went wrong")), running("h3")),
		},
	} {
		t.Run(tc.golden, func(t *testing.T) {
			t.Parallel()
			testutil.AssertProtoEqual(t, readGoldenPb(t, tc.golden), snapshotToPb(tc.snap))
		})
	}
}

func TestSnapshotToPbEmpty(t *testing.T) {
	t.Parallel()

	msg := snapshotToPb(healthv2.Snapshot{})
	assert.Equal(t, healthpb.OverallStatus_OVERALL_STATUS_STARTING, msg.OverallStatus)
}

func TestCheckerToPb(t *testing.T) {
	t.Parallel()

	ok := &healthpb.Condition{Ok: true}
	failed := func(reason string) *healthpb.Condition {
		return &healthpb.Condition{Reason: new(reason)}
	}
	for _, tc := range []struct {
		name   string
		status healthv2.CheckerStatus
		want   *healthpb.ComponentStatus
	}{
		{
			name:   "ok",
			status: running("a"),
			want: &healthpb.ComponentStatus{
				Status:      healthpb.HealthStatus_HEALTH_STATUS_RUNNING,
				Initialized: ok, Ready: ok, Healthy: ok,
			},
		},
		{
			name:   "starting",
			status: uninitialized(running("a"), "loading"),
			want: &healthpb.ComponentStatus{
				Status: healthpb.HealthStatus_HEALTH_STATUS_STARTING, Err: new("loading"),
				Initialized: failed("loading"), Ready: failed("loading"), Healthy: ok,
			},
		},
		{
			name:   "not_ready",
			status: checkerStatus("a", fail("syncing"), pass(nil)),
			want: &healthpb.ComponentStatus{
				Status: healthpb.HealthStatus_HEALTH_STATUS_NOT_READY, Err: new("syncing"),
				Initialized: ok, Ready: failed("syncing"), Healthy: ok,
			},
		},
		{
			name:   "unhealthy",
			status: checkerStatus("a", pass(nil), fail("boom")),
			want: &healthpb.ComponentStatus{
				Status: healthpb.HealthStatus_HEALTH_STATUS_UNHEALTHY, Err: new("boom"),
				Initialized: ok, Ready: ok, Healthy: failed("boom"),
			},
		},
		{
			name:   "healthy_first",
			status: checkerStatus("a", fail("syncing"), fail("boom")),
			want: &healthpb.ComponentStatus{
				Status: healthpb.HealthStatus_HEALTH_STATUS_UNHEALTHY, Err: new("boom"),
				Initialized: ok, Ready: failed("syncing"), Healthy: failed("boom"),
			},
		},
		{
			name:   "no_reason",
			status: checkerStatus("a", fail(""), pass(nil)),
			want: &healthpb.ComponentStatus{
				Status: healthpb.HealthStatus_HEALTH_STATUS_NOT_READY, Err: new(""),
				Initialized: ok, Ready: &healthpb.Condition{}, Healthy: ok,
			},
		},
		{
			name: "attributes",
			status: healthv2.CheckerStatus{
				Service:     healthv2.ServiceProxy,
				Name:        "a",
				Initialized: pass(map[string]string{"shared": "i"}),
				Ready:       pass(map[string]string{"role": "follower", "shared": "r"}),
				Healthy:     pass(map[string]string{"shared": "h"}),
			},
			want: &healthpb.ComponentStatus{
				Status:      healthpb.HealthStatus_HEALTH_STATUS_RUNNING,
				Initialized: ok, Ready: ok, Healthy: ok,
				Attributes: map[string]string{
					"initialized.shared": "i",
					"ready.role":         "follower",
					"ready.shared":       "r",
					"healthy.shared":     "h",
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			testutil.AssertProtoEqual(t, tc.want, checkerToPb(tc.status))
		})
	}
}

func TestGRPCStream(t *testing.T) {
	t.Parallel()

	h1, h2, h3 := newChecker("h1"), newChecker("h2"), newChecker("h3")
	sharedKey := []byte("key")
	sink := NewGRPC(time.Millisecond, func() []byte {
		return sharedKey
	})

	m := healthv2.NewManager(healthv2.Options{PollInterval: time.Millisecond})
	for _, c := range []*testChecker{h1, h2, h3} {
		m.RegisterHealthChecker(c)
	}
	m.RegisterSink(sink)
	runManager(t, m)
	require.Eventually(t, func() bool { return m.Snapshot().Ready() }, time.Second, time.Millisecond)

	cc := testutil.NewGRPCServer(t, func(s *grpc.Server) {
		healthpb.RegisterHealthNotifierServer(s, sink)
	}, grpc.WithStreamInterceptor(grpcutil.WithStreamSignedJWT(func() []byte { return sharedKey })))
	streams := make([]grpc.ServerStreamingClient[healthpb.HealthMessage], 2)
	for i := range streams {
		var err error
		streams[i], err = healthpb.NewHealthNotifierClient(cc).SyncHealth(t.Context(), &healthpb.HealthStreamRequest{})
		require.NoError(t, err)
	}

	ok := &healthpb.Condition{Ok: true}
	runningPb := func() *healthpb.ComponentStatus {
		return &healthpb.ComponentStatus{Status: healthpb.HealthStatus_HEALTH_STATUS_RUNNING, Initialized: ok, Ready: ok, Healthy: ok}
	}
	initial := &healthpb.HealthMessage{
		OverallStatus: healthpb.OverallStatus_OVERALL_STATUS_RUNNING,
		Statuses: map[string]*healthpb.ComponentStatus{
			"Proxy/h1": runningPb(),
			"Proxy/h2": runningPb(),
			"Proxy/h3": runningPb(),
		},
		Required: []string{"Proxy/h1", "Proxy/h2", "Proxy/h3"},
	}
	for _, s := range streams {
		msg, err := s.Recv()
		require.NoError(t, err)
		testutil.AssertProtoEqual(t, initial, msg)
	}

	h2.set(pass(nil), fail("something went wrong"))
	want := readGoldenPb(t, "grpc_unhealthy.json")
	for _, s := range streams {
		for {
			msg, err := s.Recv()
			require.NoError(t, err)
			if proto.Equal(want, msg) {
				break
			}
			testutil.AssertProtoEqual(t, initial, msg, "only the previous state may be repeated")
		}
	}
}

func TestGRPCRejectsUnsigned(t *testing.T) {
	t.Parallel()

	sink := NewGRPC(time.Millisecond, func() []byte {
		return []byte("key")
	})
	cc := testutil.NewGRPCServer(t, func(s *grpc.Server) {
		healthpb.RegisterHealthNotifierServer(s, sink)
	}, grpc.WithStreamInterceptor(grpcutil.WithStreamSignedJWT(func() []byte { return []byte("wrong") })))

	stream, err := healthpb.NewHealthNotifierClient(cc).SyncHealth(t.Context(), &healthpb.HealthStreamRequest{})
	require.NoError(t, err)
	_, err = stream.Recv()
	require.Error(t, err)
}
