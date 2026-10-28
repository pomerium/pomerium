package databroker_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc"

	"github.com/pomerium/pomerium/internal/databroker"
	"github.com/pomerium/pomerium/internal/testutil"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

// stallingLeader serves SyncLatest by sending its records and then blocking
// until the stream is cancelled, without ever sending the final versions.
type stallingLeader struct {
	databrokerpb.UnimplementedDataBrokerServiceServer
	records []*databrokerpb.Record
	stalled chan struct{}
}

func (srv *stallingLeader) SyncLatest(_ *databrokerpb.SyncLatestRequest, stream grpc.ServerStreamingServer[databrokerpb.SyncLatestResponse]) error {
	for _, record := range srv.records {
		err := stream.Send(&databrokerpb.SyncLatestResponse{
			Response: &databrokerpb.SyncLatestResponse_Record{Record: record},
		})
		if err != nil {
			return err
		}
	}
	close(srv.stalled)
	<-stream.Context().Done()
	return stream.Context().Err()
}

func TestClusteredFollowerServer_ResyncKeepsLocalRecords(t *testing.T) {
	ctx := t.Context()

	leader := &stallingLeader{
		records: []*databrokerpb.Record{{Type: "example", Id: "from-leader", Data: protoutil.NewAnyString("leader")}},
		stalled: make(chan struct{}),
	}
	leaderCC := testutil.NewGRPCServer(t, func(s *grpc.Server) {
		databrokerpb.RegisterDataBrokerServiceServer(s, leader)
	})

	local := databroker.NewBackendServer(noop.NewTracerProvider())
	_, err := local.Put(ctx, &databrokerpb.PutRequest{
		Records: []*databrokerpb.Record{{Type: "example", Id: "existing", Data: protoutil.NewAnyString("local")}},
	})
	require.NoError(t, err)

	follower := databroker.NewClusteredFollowerServer(noop.NewTracerProvider(), local, leaderCC)
	t.Cleanup(follower.Stop)

	select {
	case <-leader.stalled:
	case <-time.After(10 * time.Second):
		t.Fatal("the follower never resynced from the leader")
	}

	res, err := local.Get(ctx, &databrokerpb.GetRequest{Type: "example", Id: "existing"})
	require.NoError(t, err,
		"a record in the local store must still be there while a resync from the leader is incomplete")
	require.NotNil(t, res.GetRecord())
}
