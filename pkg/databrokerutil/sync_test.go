package databrokerutil_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc"

	"github.com/pomerium/pomerium/internal/databroker"
	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/pkg/databrokerutil"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	userpb "github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

type mockServer struct {
	databrokerpb.DataBrokerServiceServer

	syncLatest func(empty *databrokerpb.SyncLatestRequest, server databrokerpb.DataBrokerService_SyncLatestServer) error
}

func (m *mockServer) SyncLatest(req *databrokerpb.SyncLatestRequest, stream databrokerpb.DataBrokerService_SyncLatestServer) error {
	return m.syncLatest(req, stream)
}

func TestInitialSync(t *testing.T) {
	t.Parallel()

	ctx, clearTimeout := context.WithTimeout(t.Context(), time.Second*10)
	defer clearTimeout()

	li, err := net.Listen("tcp", "127.0.0.1:0")
	if !assert.NoError(t, err) {
		return
	}
	defer li.Close()

	r1 := new(databrokerpb.Record)
	r2 := new(databrokerpb.Record)

	o1 := new(databrokerpb.TypedOptions)

	m := &mockServer{
		syncLatest: func(_ *databrokerpb.SyncLatestRequest, stream databrokerpb.DataBrokerService_SyncLatestServer) error {
			stream.Send(&databrokerpb.SyncLatestResponse{
				Response: &databrokerpb.SyncLatestResponse_Record{
					Record: r1,
				},
			})
			stream.Send(&databrokerpb.SyncLatestResponse{
				Response: &databrokerpb.SyncLatestResponse_Record{
					Record: r2,
				},
			})
			stream.Send(&databrokerpb.SyncLatestResponse{
				Response: &databrokerpb.SyncLatestResponse_Versions{
					Versions: &databrokerpb.Versions{
						LatestRecordVersion: 2,
						ServerVersion:       1,
					},
				},
			})

			stream.Send(&databrokerpb.SyncLatestResponse{
				Response: &databrokerpb.SyncLatestResponse_Options{
					Options: o1,
				},
			})
			return nil
		},
	}

	srv := grpc.NewServer()
	databrokerpb.RegisterDataBrokerServiceServer(srv, m)
	go srv.Serve(li)

	cc, err := grpc.Dial(li.Addr().String(), grpc.WithInsecure())
	if !assert.NoError(t, err) {
		return
	}
	defer cc.Close()

	c := databrokerpb.NewDataBrokerServiceClient(cc)

	records, options, recordVersion, serverVersion, err := databrokerutil.InitialSync(ctx, c, new(databrokerpb.SyncLatestRequest))
	assert.NoError(t, err)
	assert.Equal(t, uint64(2), recordVersion)
	assert.Equal(t, uint64(1), serverVersion)
	testutil.AssertProtoEqual(t, []*databrokerpb.Record{r1, r2}, records)
	testutil.AssertProtoEqual(t, []*databrokerpb.TypedOptions{o1}, options)
}

func Test_SyncLatestRecords(t *testing.T) {
	t.Parallel()

	ctx, clearTimeout := context.WithTimeout(t.Context(), time.Minute)
	defer clearTimeout()

	srv := databroker.NewBackendServer(noop.NewTracerProvider())
	t.Cleanup(srv.Stop)

	cc := testutil.NewGRPCServer(t, func(s *grpc.Server) {
		databrokerpb.RegisterDataBrokerServiceServer(s, srv)
	})

	c := databrokerpb.NewDataBrokerServiceClient(cc)

	expected := []*userpb.User{
		{Id: "u1"},
		{Id: "u2"},
		{Id: "u3"},
	}

	for _, u := range expected {
		_, err := c.Put(ctx, &databrokerpb.PutRequest{
			Records: []*databrokerpb.Record{
				databrokerpb.NewRecord(u),
			},
		})
		require.NoError(t, err)
	}

	// add a non-user record to make sure it gets ignored
	_, err := c.Put(ctx, &databrokerpb.PutRequest{
		Records: []*databrokerpb.Record{
			{
				Id:   "u4",
				Type: protoutil.GetTypeURL(new(userpb.User)),
				Data: protoutil.NewAny(&session.Session{Id: "s1"}),
			},
		},
	})
	require.NoError(t, err)

	var actual []*userpb.User
	serverVersion, latestRecordVersion, err := databrokerutil.SyncLatestRecords(t.Context(), c, func(u *userpb.User) {
		actual = append(actual, u)
	})
	assert.NoError(t, err)
	assert.NotZero(t, serverVersion)
	assert.Equal(t, uint64(4), latestRecordVersion)
	testutil.AssertProtoEqual(t, expected, actual)
}
