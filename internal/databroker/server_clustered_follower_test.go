package databroker_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/pomerium/pomerium/internal/databroker"
	"github.com/pomerium/pomerium/internal/testutil"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpcutil"
)

func TestClusteredFollowerServer(t *testing.T) {
	t.Parallel()

	t.Run("default", func(t *testing.T) {
		t.Parallel()

		leader := databroker.NewBackendServer(noop.NewTracerProvider())
		leaderCC := testutil.NewGRPCServer(t, func(s *grpc.Server) {
			databrokerpb.RegisterDataBrokerServiceServer(s, leader)
		})
		local := databroker.NewBackendServer(noop.NewTracerProvider())
		follower := databroker.NewClusteredFollowerServer(noop.NewTracerProvider(), local, leaderCC)
		t.Cleanup(follower.Stop)
		cc := testutil.NewGRPCServer(t, func(s *grpc.Server) {
			databrokerpb.RegisterDataBrokerServiceServer(s, follower)
		})

		ctx := t.Context()

		res1, err := leader.ServerInfo(ctx, new(emptypb.Empty))
		assert.NoError(t, err)

		res2, err := databrokerpb.NewDataBrokerServiceClient(cc).ServerInfo(ctx, new(emptypb.Empty))
		assert.NoError(t, err)

		assert.Empty(t, cmp.Diff(res1, res2, protocmp.Transform()))
	})
	t.Run("explicit default", func(t *testing.T) {
		t.Parallel()

		leader := databroker.NewBackendServer(noop.NewTracerProvider())
		leaderCC := testutil.NewGRPCServer(t, func(s *grpc.Server) {
			databrokerpb.RegisterDataBrokerServiceServer(s, leader)
		})
		local := databroker.NewBackendServer(noop.NewTracerProvider())
		follower := databroker.NewClusteredFollowerServer(noop.NewTracerProvider(), local, leaderCC)
		t.Cleanup(follower.Stop)
		cc := testutil.NewGRPCServer(t, func(s *grpc.Server) {
			databrokerpb.RegisterDataBrokerServiceServer(s, follower)
		})

		ctx := databrokerpb.WithOutgoingClusterRequestMode(t.Context(), databrokerpb.ClusterRequestModeDefault)

		res1, err := leader.ServerInfo(ctx, new(emptypb.Empty))
		assert.NoError(t, err)

		res2, err := databrokerpb.NewDataBrokerServiceClient(cc).ServerInfo(ctx, new(emptypb.Empty))
		assert.NoError(t, err)

		assert.Empty(t, cmp.Diff(res1, res2, protocmp.Transform()))
	})
	t.Run("leader", func(t *testing.T) {
		t.Parallel()

		leader := databroker.NewBackendServer(noop.NewTracerProvider())
		leaderCC := testutil.NewGRPCServer(t, func(s *grpc.Server) {
			databrokerpb.RegisterDataBrokerServiceServer(s, leader)
		})
		local := databroker.NewBackendServer(noop.NewTracerProvider())
		follower := databroker.NewClusteredFollowerServer(noop.NewTracerProvider(), local, leaderCC)
		t.Cleanup(follower.Stop)
		cc := testutil.NewGRPCServer(t, func(s *grpc.Server) {
			databrokerpb.RegisterDataBrokerServiceServer(s, follower)
		})

		ctx := databrokerpb.WithOutgoingClusterRequestMode(t.Context(), databrokerpb.ClusterRequestModeLeader)

		_, err := databrokerpb.NewDataBrokerServiceClient(cc).ServerInfo(ctx, new(emptypb.Empty))
		assert.ErrorIs(t, err, databrokerpb.ErrNodeIsNotLeader)
	})
	t.Run("local", func(t *testing.T) {
		t.Parallel()

		leader := databroker.NewBackendServer(noop.NewTracerProvider())
		leaderCC := testutil.NewGRPCServer(t, func(s *grpc.Server) {
			databrokerpb.RegisterDataBrokerServiceServer(s, leader)
		})
		local := databroker.NewBackendServer(noop.NewTracerProvider())
		follower := databroker.NewClusteredFollowerServer(noop.NewTracerProvider(), local, leaderCC)
		t.Cleanup(follower.Stop)
		cc := testutil.NewGRPCServer(t, func(s *grpc.Server) {
			databrokerpb.RegisterDataBrokerServiceServer(s, follower)
		})

		ctx := databrokerpb.WithOutgoingClusterRequestMode(t.Context(), databrokerpb.ClusterRequestModeLocal)
		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			res1, err := local.ServerInfo(ctx, new(emptypb.Empty))
			assert.NoError(c, err)

			res2, err := databrokerpb.NewDataBrokerServiceClient(cc).ServerInfo(ctx, new(emptypb.Empty))
			assert.NoError(c, err)

			assert.Empty(c, cmp.Diff(res1, res2, protocmp.Transform()))
		}, time.Second*3, time.Millisecond*30)
	})
	t.Run("local write", func(t *testing.T) {
		t.Parallel()

		leader := databroker.NewBackendServer(noop.NewTracerProvider())
		leaderCC := testutil.NewGRPCServer(t, func(s *grpc.Server) {
			databrokerpb.RegisterDataBrokerServiceServer(s, leader)
		})
		local := databroker.NewBackendServer(noop.NewTracerProvider())
		follower := databroker.NewClusteredFollowerServer(noop.NewTracerProvider(), local, leaderCC)
		t.Cleanup(follower.Stop)
		followerCC := testutil.NewGRPCServer(t, func(s *grpc.Server) {
			databrokerpb.RegisterDataBrokerServiceServer(s, follower)
		})

		ctx := databrokerpb.WithOutgoingClusterRequestMode(t.Context(), databrokerpb.ClusterRequestModeLocal)

		_, err := databrokerpb.NewDataBrokerServiceClient(followerCC).Put(ctx, &databrokerpb.PutRequest{})
		assert.ErrorIs(t, err, databrokerpb.ErrNodeIsNotLeader)
	})
	t.Run("sync", func(t *testing.T) {
		t.Parallel()

		leader := databroker.NewBackendServer(noop.NewTracerProvider())
		leaderCC := testutil.NewGRPCServer(t, func(s *grpc.Server) {
			databrokerpb.RegisterDataBrokerServiceServer(s, leader)
		})
		local := databroker.NewBackendServer(noop.NewTracerProvider())

		_, err := local.Put(t.Context(), &databrokerpb.PutRequest{
			Records: []*databrokerpb.Record{
				databrokerpb.NewRecord(&session.Session{
					Id: "local-1",
				}),
			},
		})
		require.NoError(t, err)

		follower := databroker.NewClusteredFollowerServer(noop.NewTracerProvider(), local, leaderCC)
		t.Cleanup(follower.Stop)

		for i := range 100 {
			_, err = databrokerpb.NewDataBrokerServiceClient(leaderCC).Put(t.Context(), &databrokerpb.PutRequest{
				Records: []*databrokerpb.Record{
					databrokerpb.NewRecord(&session.Session{
						Id: fmt.Sprintf("remote-%d", i+1),
					}),
				},
			})
			require.NoError(t, err)
		}

		assert.Eventually(t, func() bool {
			_, err := local.Get(t.Context(), &databrokerpb.GetRequest{
				Type: grpcutil.GetTypeURL(new(session.Session)),
				Id:   "remote-100",
			})
			return err == nil
		}, 10*time.Second, 10*time.Millisecond, "should sync remote records")

		_, err = local.Get(t.Context(), &databrokerpb.GetRequest{
			Type: grpcutil.GetTypeURL(new(session.Session)),
			Id:   "local-1",
		})
		assert.Equal(t, codes.NotFound, status.Code(err), "should clear local records during sync")
	})
	t.Run("checkpoints", func(t *testing.T) {
		leader := databroker.NewBackendServer(noop.NewTracerProvider())
		leaderCC := testutil.NewGRPCServer(t, func(s *grpc.Server) {
			databrokerpb.RegisterDataBrokerServiceServer(s, leader)
		})
		local := databroker.NewBackendServer(noop.NewTracerProvider())

		follower := databroker.NewClusteredFollowerServer(noop.NewTracerProvider(), local, leaderCC)
		t.Cleanup(follower.Stop)

		cp1 := &databrokerpb.Checkpoint{
			ServerVersion: 100,
			RecordVersion: 101,
		}
		cp2 := &databrokerpb.Checkpoint{
			ServerVersion: 200,
			RecordVersion: 201,
		}
		cp3 := &databrokerpb.Checkpoint{
			ServerVersion: 300,
			RecordVersion: 301,
		}

		leader.SetCheckpoint(t.Context(), &databrokerpb.SetCheckpointRequest{Checkpoint: cp1})
		local.SetCheckpoint(t.Context(), &databrokerpb.SetCheckpointRequest{Checkpoint: cp2})

		res, err := follower.GetCheckpoint(t.Context(), &databrokerpb.GetCheckpointRequest{})
		assert.NoError(t, err)
		assert.Empty(t, cmp.Diff(cp2, res.GetCheckpoint(), protocmp.Transform()),
			"should return the local checkpoint")

		_, err = follower.SetCheckpoint(t.Context(), &databrokerpb.SetCheckpointRequest{Checkpoint: cp3})
		assert.ErrorIs(t, err, databrokerpb.ErrSetCheckpointNotSupported,
			"should not allow setting checkpoints")
	})
}
