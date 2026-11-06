package databroker_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"

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

func TestClusteredFollowerServer_ResyncReplacesLocalRecords(t *testing.T) {
	ctx := t.Context()

	put := func(srv databroker.Server, records ...*databrokerpb.Record) {
		t.Helper()
		_, err := srv.Put(ctx, &databrokerpb.PutRequest{Records: records})
		require.NoError(t, err)
	}
	get := func(srv databroker.Server, recordType, recordID string) *databrokerpb.Record {
		t.Helper()
		res, err := srv.Get(ctx, &databrokerpb.GetRequest{Type: recordType, Id: recordID})
		if status.Code(err) == codes.NotFound {
			return nil
		}
		require.NoError(t, err)
		return res.GetRecord()
	}

	leader := databroker.NewBackendServer(noop.NewTracerProvider())
	put(leader,
		&databrokerpb.Record{Type: "example", Id: "unchanged", Data: protoutil.NewAnyString("same")},
		&databrokerpb.Record{Type: "example", Id: "changed", Data: protoutil.NewAnyString("new")},
		&databrokerpb.Record{Type: "example", Id: "added", Data: protoutil.NewAnyString("added")},
	)
	leaderCC := testutil.NewGRPCServer(t, func(s *grpc.Server) {
		databrokerpb.RegisterDataBrokerServiceServer(s, leader)
	})

	local := databroker.NewBackendServer(noop.NewTracerProvider())
	put(local,
		&databrokerpb.Record{Type: "example", Id: "unchanged", Data: protoutil.NewAnyString("same")},
		&databrokerpb.Record{Type: "example", Id: "changed", Data: protoutil.NewAnyString("old")},
		&databrokerpb.Record{Type: "example", Id: "removed", Data: protoutil.NewAnyString("removed")},
		&databrokerpb.Record{Type: "removed-type", Id: "removed", Data: protoutil.NewAnyString("removed")},
	)
	_, err := local.SetOptions(ctx, &databrokerpb.SetOptionsRequest{
		Type:    "removed-type",
		Options: &databrokerpb.Options{Capacity: proto.Uint64(10)},
	})
	require.NoError(t, err)
	unchangedVersion := get(local, "example", "unchanged").GetVersion()

	leaderInfo, err := leader.ServerInfo(ctx, new(emptypb.Empty))
	require.NoError(t, err)

	follower := databroker.NewClusteredFollowerServer(noop.NewTracerProvider(), local, leaderCC)
	t.Cleanup(follower.Stop)

	require.Eventually(t, func() bool {
		res, err := local.GetCheckpoint(ctx, new(databrokerpb.GetCheckpointRequest))
		return err == nil && res.GetCheckpoint().GetServerVersion() == leaderInfo.GetServerVersion()
	}, 10*time.Second, 10*time.Millisecond, "the follower never stored the leader's checkpoint")

	assert.Equal(t, unchangedVersion, get(local, "example", "unchanged").GetVersion(),
		"a record with the same data as the leader's must not be rewritten")
	assert.True(t, proto.Equal(protoutil.NewAnyString("new"), get(local, "example", "changed").GetData()),
		"a record whose data differs from the leader's must be updated")
	assert.NotNil(t, get(local, "example", "added"))
	assert.Nil(t, get(local, "example", "removed"),
		"a record the leader does not have must be removed")
	assert.Nil(t, get(local, "removed-type", "removed"))
	_, err = local.GetOptions(ctx, &databrokerpb.GetOptionsRequest{Type: "removed-type"})
	assert.Equal(t, codes.NotFound, status.Code(err),
		"options for a type the leader does not have must be removed")
}
