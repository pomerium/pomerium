package health

import (
	"fmt"
	"testing"
	"time"

	healthpb "github.com/pomerium/pomerium/pkg/grpc/health"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/internal/testutil"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

func ConnFromServer(t *testing.T, srv *GRPCStreamProvider) *grpc.ClientConn {
	t.Helper()
	cc := testutil.NewGRPCServer(t, func(s *grpc.Server) {
		healthpb.RegisterHealthNotifierServer(s, srv)
	})
	t.Cleanup(func() { cc.Close() })
	return cc
}

func TestGrpcStream(t *testing.T) {
	t.Parallel()
	h1, h2, h3 := Check("h1"), Check("h2"), Check("h3")
	fmt.Println(h1, h2, h3)
	mgr := NewManager()
	g := NewGRPCStreamProvider(t.Context(), mgr, time.Millisecond, WithExpectedChecks(
		h1, h2, h3,
	))
	mgr.Register(ProviderGRPCStream, g)
	cc := ConnFromServer(t, g)

	client1 := healthpb.NewHealthNotifierClient(cc)
	client2 := healthpb.NewHealthNotifierClient(cc)

	sc1, err := client1.SyncHealth(t.Context(), &emptypb.Empty{})
	require.NoError(t, err)

	sc2, err := client2.SyncHealth(t.Context(), &emptypb.Empty{})
	require.NoError(t, err)

	firstMessage := &healthpb.HealthMessage{
		OverallStatus: healthpb.OverallStatus_StatusStarting,
		OverallErr:    proto.String("3 component(s) not started: h1,h2,h3"),
		Required:      []string{"h1", "h2", "h3"},
	}

	msg1, err := sc1.Recv()
	assert.NoError(t, err)
	assert.NotNil(t, msg1)
	testutil.AssertProtoEqual(t, firstMessage, msg1)
	msg2, err := sc2.Recv()
	assert.NoError(t, err)
	assert.NotNil(t, msg2)
	testutil.AssertProtoEqual(t, firstMessage, msg2)

	mgr.ReportStatus(h1, StatusRunning)
	mgr.ReportStatus(h2, StatusRunning, StrAttr("foo", "bar"))
	secondMsg := &healthpb.HealthMessage{
		OverallStatus: healthpb.OverallStatus_StatusStarting,
		OverallErr:    proto.String("1 component(s) not started: h3"),
		Statuses: map[string]*healthpb.ComponentStatus{
			"h1": {
				Status: healthpb.HealthStatus_Running,
			},
			"h2": {
				Status: healthpb.HealthStatus_Running,
				Attributes: map[string]string{
					"foo": "bar",
				},
			},
		},
		Required: []string{"h1", "h2", "h3"},
	}
	msg1, err = sc1.Recv()
	assert.NoError(t, err)
	assert.NotNil(t, msg1)
	testutil.AssertProtoEqual(t, secondMsg, msg1)
	msg2, err = sc2.Recv()
	assert.NoError(t, err)
	assert.NotNil(t, msg2)
	testutil.AssertProtoEqual(t, secondMsg, msg2)

	mgr.ReportError(h2, fmt.Errorf("something went wrong"))
	mgr.ReportStatus(h3, StatusRunning)

	thirdMsg := &healthpb.HealthMessage{
		OverallStatus: healthpb.OverallStatus_StatusRunning,
		OverallErr:    proto.String("1 component(s) not healthy: h2"),
		Statuses: map[string]*healthpb.ComponentStatus{
			"h1": {
				Status: healthpb.HealthStatus_Running,
			},
			"h2": {
				Status: healthpb.HealthStatus_Running,
				Err:    proto.String("something went wrong"),
			},
			"h3": {
				Status: healthpb.HealthStatus_Running,
			},
		},
		Required: []string{"h1", "h2", "h3"},
	}

	msg1, err = sc1.Recv()
	assert.NoError(t, err)
	assert.NotNil(t, msg1)
	testutil.AssertProtoEqual(t, thirdMsg, msg1)
	msg2, err = sc2.Recv()
	assert.NoError(t, err)
	assert.NotNil(t, msg2)
	testutil.AssertProtoEqual(t, thirdMsg, msg2)

	mgr.ReportStatus(h2, StatusRunning)

	fourthMessage := &healthpb.HealthMessage{
		OverallStatus: healthpb.OverallStatus_StatusRunning,
		Statuses: map[string]*healthpb.ComponentStatus{
			"h1": {
				Status: healthpb.HealthStatus_Running,
			},
			"h2": {
				Status: healthpb.HealthStatus_Running,
			},
			"h3": {
				Status: healthpb.HealthStatus_Running,
			},
		},
		Required: []string{"h1", "h2", "h3"},
	}

	msg1, err = sc1.Recv()
	assert.NoError(t, err)
	assert.NotNil(t, msg1)
	testutil.AssertProtoEqual(t, fourthMessage, msg1)
	msg2, err = sc2.Recv()
	assert.NoError(t, err)
	assert.NotNil(t, msg2)
	testutil.AssertProtoEqual(t, fourthMessage, msg2)

	mgr.ReportStatus(h1, StatusTerminating)

	fifthMessage := &healthpb.HealthMessage{
		OverallStatus: healthpb.OverallStatus_StatusTerminating,
		Statuses: map[string]*healthpb.ComponentStatus{
			"h1": {
				Status: healthpb.HealthStatus_Terminating,
			},
			"h2": {
				Status: healthpb.HealthStatus_Running,
			},
			"h3": {
				Status: healthpb.HealthStatus_Running,
			},
		},
		Required: []string{"h1", "h2", "h3"},
	}

	msg1, err = sc1.Recv()
	assert.NoError(t, err)
	assert.NotNil(t, msg1)
	testutil.AssertProtoEqual(t, fifthMessage, msg1)
	msg2, err = sc2.Recv()
	assert.NoError(t, err)
	assert.NotNil(t, msg2)
	testutil.AssertProtoEqual(t, fifthMessage, msg2)

	mgr.ReportError(h3, fmt.Errorf("not terminating"))

	sixthMessage := &healthpb.HealthMessage{
		OverallStatus: healthpb.OverallStatus_StatusTerminating,
		OverallErr:    proto.String("1 component(s) not healthy: h3"),
		Statuses: map[string]*healthpb.ComponentStatus{
			"h1": {
				Status: healthpb.HealthStatus_Terminating,
			},
			"h2": {
				Status: healthpb.HealthStatus_Running,
			},
			"h3": {
				Status: healthpb.HealthStatus_Running,
				Err:    proto.String("not terminating"),
			},
		},
		Required: []string{"h1", "h2", "h3"},
	}

	msg1, err = sc1.Recv()
	assert.NoError(t, err)
	assert.NotNil(t, msg1)
	testutil.AssertProtoEqual(t, sixthMessage, msg1)
	msg2, err = sc2.Recv()
	assert.NoError(t, err)
	assert.NotNil(t, msg2)
	testutil.AssertProtoEqual(t, sixthMessage, msg2)

}

func TestConvert(t *testing.T) {
	type tc struct {
		contents map[Check]*Record
		required []Check
		expected *healthpb.HealthMessage
	}

	tcs := []tc{
		{
			contents: map[Check]*Record{
				"h1": newRecord(StatusRunning, nil, []Attr{{Key: "foo", Value: "bar"}}),
			},
			required: []Check{},
			expected: &healthpb.HealthMessage{
				OverallStatus: healthpb.OverallStatus_StatusRunning,
				Statuses: map[string]*healthpb.ComponentStatus{
					"h1": {
						Status: healthpb.HealthStatus_Running,
						Attributes: map[string]string{
							"foo": "bar",
						},
					},
				},
			},
		},
	}

	for _, tc := range tcs {
		msg := ConvertRecordsToPb(tc.contents, tc.required)
		testutil.AssertProtoEqual(t, tc.expected, msg)
	}
}
