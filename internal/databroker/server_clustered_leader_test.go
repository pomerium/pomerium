package databroker_test

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/pomerium/pomerium/internal/databroker"
	"github.com/pomerium/pomerium/internal/testutil"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
)

func TestClusteredLeaderServer(t *testing.T) {
	t.Parallel()

	t.Run("server info", func(t *testing.T) {
		t.Parallel()

		local := databroker.NewBackendServer(noop.NewTracerProvider())
		leader := databroker.NewClusteredLeaderServer(local)

		cc := testutil.NewGRPCServer(t, func(s *grpc.Server) {
			databrokerpb.RegisterDataBrokerServiceServer(s, leader)
		})

		res1, err := local.ServerInfo(t.Context(), new(emptypb.Empty))
		assert.NoError(t, err)
		res2, err := databrokerpb.NewDataBrokerServiceClient(cc).ServerInfo(t.Context(), new(emptypb.Empty))
		assert.NoError(t, err)

		assert.Empty(t, cmp.Diff(res1, res2, protocmp.Transform()))
	})

	t.Run("checkpoints", func(t *testing.T) {
		t.Parallel()

		local := databroker.NewBackendServer(noop.NewTracerProvider())
		leader := databroker.NewClusteredLeaderServer(local)

		_, err := leader.Put(t.Context(), &databrokerpb.PutRequest{
			Records: []*databrokerpb.Record{
				databrokerpb.NewRecord(&session.Session{
					Id: "local-1",
				}),
			},
		})
		require.NoError(t, err)

		info, err := local.ServerInfo(t.Context(), new(emptypb.Empty))
		require.NoError(t, err)

		assert.Eventually(t, func() bool {
			res, err := leader.GetCheckpoint(t.Context(), &databrokerpb.GetCheckpointRequest{})
			assert.NoError(t, err)
			return res.GetCheckpoint().GetServerVersion() == info.GetServerVersion()
		}, time.Second, 50*time.Millisecond, "should update checkpoint")

		_, err = leader.SetCheckpoint(t.Context(), &databrokerpb.SetCheckpointRequest{})
		assert.ErrorIs(t, err, databrokerpb.ErrSetCheckpointNotSupported,
			"should not allow setting checkpoints")
	})
}
