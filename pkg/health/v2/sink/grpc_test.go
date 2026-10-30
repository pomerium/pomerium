package sink

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/testutil"
	healthpb "github.com/pomerium/pomerium/pkg/grpc/health"
	"github.com/pomerium/pomerium/pkg/grpcutil"
	healthv2 "github.com/pomerium/pomerium/pkg/health/v2"
	"github.com/pomerium/pomerium/pkg/health/v2/check"
)

func readGoldenPb(t *testing.T, name string) *healthpb.HealthMessage {
	t.Helper()
	msg := &healthpb.HealthMessage{}
	require.NoError(t, protojson.Unmarshal(readGolden(t, name), msg))
	return msg
}

func TestSnapshotToPbWireCompat(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		golden string
		snap   healthv2.Snapshot
	}{
		{
			golden: "grpc_starting.json",
			snap: healthv2.Snapshot{Configured: true, Checkers: []healthv2.CheckerStatus{
				checkerStatus("", "c", running("h1"), running("h2", check.Attr{Key: "foo", Value: "bar"})),
				checkerStatus("", "h3", check.Result{Name: "h3"}),
			}},
		},
		{
			golden: "grpc_unhealthy.json",
			snap:   snapshotOf(running("h1"), failing("h2", check.StatusRunning, "something went wrong"), running("h3")),
		},
		{
			golden: "grpc_terminating.json",
			snap:   snapshotOf(terminating("h1"), running("h2"), failing("h3", check.StatusRunning, "not terminating")),
		},
	} {
		t.Run(tc.golden, func(t *testing.T) {
			t.Parallel()
			testutil.AssertProtoEqual(t, readGoldenPb(t, tc.golden), snapshotToPb(tc.snap))
		})
	}
}

func TestSnapshotToPbNotConfigured(t *testing.T) {
	t.Parallel()

	msg := snapshotToPb(healthv2.Snapshot{})
	assert.Equal(t, healthpb.OverallStatus_OVERALL_STATUS_STARTING, msg.OverallStatus)
}

func TestGRPCStream(t *testing.T) {
	t.Parallel()

	c := newChecker(running("h1"), running("h2", check.Attr{Key: "foo", Value: "bar"}), running("h3"))
	sharedKey := []byte("key")
	sink := NewGRPC(time.Millisecond, sharedKey)

	m := healthv2.NewManager(healthv2.Options{PollInterval: time.Millisecond})
	m.ConfigureChecks(&config.Options{})
	m.RegisterChecker(c)
	m.RegisterSink(sink)
	t.Cleanup(m.Close)
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

	initial := &healthpb.HealthMessage{
		OverallStatus: healthpb.OverallStatus_OVERALL_STATUS_RUNNING,
		Statuses: map[string]*healthpb.ComponentStatus{
			"h1": {Status: healthpb.HealthStatus_HEALTH_STATUS_RUNNING},
			"h2": {Status: healthpb.HealthStatus_HEALTH_STATUS_RUNNING, Attributes: map[string]string{"foo": "bar"}},
			"h3": {Status: healthpb.HealthStatus_HEALTH_STATUS_RUNNING},
		},
		Required: []string{"h1", "h2", "h3"},
	}
	for _, s := range streams {
		msg, err := s.Recv()
		require.NoError(t, err)
		testutil.AssertProtoEqual(t, initial, msg)
	}

	c.set(running("h1"), failing("h2", check.StatusRunning, "something went wrong"), running("h3"))
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

	sink := NewGRPC(time.Millisecond, []byte("key"))
	t.Cleanup(sink.Close)
	cc := testutil.NewGRPCServer(t, func(s *grpc.Server) {
		healthpb.RegisterHealthNotifierServer(s, sink)
	}, grpc.WithStreamInterceptor(grpcutil.WithStreamSignedJWT(func() []byte { return []byte("wrong") })))

	stream, err := healthpb.NewHealthNotifierClient(cc).SyncHealth(t.Context(), &healthpb.HealthStreamRequest{})
	require.NoError(t, err)
	_, err = stream.Recv()
	require.Error(t, err)
}
