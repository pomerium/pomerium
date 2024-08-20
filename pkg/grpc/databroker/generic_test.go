package databroker_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	grpc "google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
)

func TestIterateAll(t *testing.T) {
	t.Parallel()

	ctx, clearTimeout := context.WithTimeout(context.Background(), time.Second*10)
	defer clearTimeout()

	li, err := net.Listen("tcp", "127.0.0.1:0")
	if !assert.NoError(t, err) {
		return
	}
	defer li.Close()

	r1 := databroker.NewRecord(&session.Session{
		Id: "s1",
	})
	r2 := databroker.NewRecord(&user.User{
		Id: "u1",
	})
	r3 := databroker.NewRecord(&session.Session{
		Id: "s2",
	})
	r4 := &databroker.Record{
		Id:   "unknown1",
		Type: "type.googleapis.com/session.Session",
	}

	m := &mockServer{
		syncLatest: func(req *databroker.SyncLatestRequest, stream databroker.DataBrokerService_SyncLatestServer) error {
			assert.Equal(t, "type.googleapis.com/session.Session", req.GetType())

			require.NoError(t, stream.Send(&databroker.SyncLatestResponse{
				Response: &databroker.SyncLatestResponse_Versions{
					Versions: &databroker.Versions{
						ServerVersion:       123,
						LatestRecordVersion: 1,
					},
				},
			}))

			require.NoError(t, stream.Send(&databroker.SyncLatestResponse{
				Response: &databroker.SyncLatestResponse_Record{
					Record: r1,
				},
			}))
			require.NoError(t, stream.Send(&databroker.SyncLatestResponse{
				Response: &databroker.SyncLatestResponse_Record{
					Record: r2,
				},
			}))
			require.NoError(t, stream.Send(&databroker.SyncLatestResponse{
				Response: &databroker.SyncLatestResponse_Record{
					Record: r3,
				},
			}))
			require.NoError(t, stream.Send(&databroker.SyncLatestResponse{
				Response: &databroker.SyncLatestResponse_Record{
					Record: r4,
				},
			}))

			return nil
		},
	}

	srv := grpc.NewServer()
	databroker.RegisterDataBrokerServiceServer(srv, m)
	go srv.Serve(li)

	cc, err := grpc.NewClient(li.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer cc.Close()

	var records []*databroker.Record
	c := databroker.NewDataBrokerServiceClient(cc)
	for record, err := range databroker.IterateAll[session.Session](ctx, c) {
		require.NoError(t, err)
		records = append(records, record.Record)
	}

	testutil.AssertProtoEqual(t, []*databroker.Record{r1, r3}, records)
}

type mockServer struct {
	databroker.DataBrokerServiceServer

	syncLatest func(*databroker.SyncLatestRequest, databroker.DataBrokerService_SyncLatestServer) error
}

func (m *mockServer) SyncLatest(req *databroker.SyncLatestRequest, stream databroker.DataBrokerService_SyncLatestServer) error {
	return m.syncLatest(req, stream)
}
