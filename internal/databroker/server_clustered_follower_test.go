package databroker_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/pomerium/pomerium/internal/databroker"
	"github.com/pomerium/pomerium/internal/testutil"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
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
		follower := databroker.NewClusteredFollowerServer(local, leaderCC)
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
		follower := databroker.NewClusteredFollowerServer(local, leaderCC)
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
		follower := databroker.NewClusteredFollowerServer(local, leaderCC)
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
		follower := databroker.NewClusteredFollowerServer(local, leaderCC)
		cc := testutil.NewGRPCServer(t, func(s *grpc.Server) {
			databrokerpb.RegisterDataBrokerServiceServer(s, follower)
		})

		ctx := databrokerpb.WithOutgoingClusterRequestMode(t.Context(), databrokerpb.ClusterRequestModeLocal)

		res1, err := local.ServerInfo(ctx, new(emptypb.Empty))
		assert.NoError(t, err)

		res2, err := databrokerpb.NewDataBrokerServiceClient(cc).ServerInfo(ctx, new(emptypb.Empty))
		assert.NoError(t, err)

		assert.Empty(t, cmp.Diff(res1, res2, protocmp.Transform()))
	})
	t.Run("local write", func(t *testing.T) {
		t.Parallel()

		leader := databroker.NewBackendServer(noop.NewTracerProvider())
		leaderCC := testutil.NewGRPCServer(t, func(s *grpc.Server) {
			databrokerpb.RegisterDataBrokerServiceServer(s, leader)
		})
		local := databroker.NewBackendServer(noop.NewTracerProvider())
		follower := databroker.NewClusteredFollowerServer(local, leaderCC)
		cc := testutil.NewGRPCServer(t, func(s *grpc.Server) {
			databrokerpb.RegisterDataBrokerServiceServer(s, follower)
		})

		ctx := databrokerpb.WithOutgoingClusterRequestMode(t.Context(), databrokerpb.ClusterRequestModeLocal)

		_, err := databrokerpb.NewDataBrokerServiceClient(cc).Put(ctx, &databrokerpb.PutRequest{})
		assert.ErrorIs(t, err, databrokerpb.ErrNodeIsNotLeader)
	})
}
