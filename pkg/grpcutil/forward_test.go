package grpcutil_test

import (
	"context"
	"io"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/testing/protocmp"

	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/pkg/grpcutil"
)

type mockHealthServer struct {
	check func(ctx context.Context, req *grpc_health_v1.HealthCheckRequest) (*grpc_health_v1.HealthCheckResponse, error)
	list  func(ctx context.Context, req *grpc_health_v1.HealthListRequest) (*grpc_health_v1.HealthListResponse, error)
	watch func(req *grpc_health_v1.HealthCheckRequest, stream grpc.ServerStreamingServer[grpc_health_v1.HealthCheckResponse]) error
}

func (srv mockHealthServer) Check(ctx context.Context, req *grpc_health_v1.HealthCheckRequest) (*grpc_health_v1.HealthCheckResponse, error) {
	if srv.check != nil {
		return srv.check(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "method Check not implemented")
}

func (srv mockHealthServer) List(ctx context.Context, req *grpc_health_v1.HealthListRequest) (*grpc_health_v1.HealthListResponse, error) {
	if srv.list != nil {
		return srv.list(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "method List not implemented")
}

func (srv mockHealthServer) Watch(req *grpc_health_v1.HealthCheckRequest, stream grpc.ServerStreamingServer[grpc_health_v1.HealthCheckResponse]) error {
	if srv.watch != nil {
		return srv.watch(req, stream)
	}
	return status.Error(codes.Unimplemented, "method Watch not implemented")
}

func TestForwardStream(t *testing.T) {
	t.Parallel()

	res1 := &grpc_health_v1.HealthCheckResponse{
		Status: grpc_health_v1.HealthCheckResponse_SERVING,
	}

	cc1 := testutil.NewGRPCServer(t, func(s *grpc.Server) {
		grpc_health_v1.RegisterHealthServer(s, mockHealthServer{
			watch: func(_ *grpc_health_v1.HealthCheckRequest, stream grpc.ServerStreamingServer[grpc_health_v1.HealthCheckResponse]) error {
				assert.Equal(t, []string{"TEST_VALUE"}, metadata.ValueFromIncomingContext(stream.Context(), "TEST_KEY"))
				return stream.Send(res1)
			},
		})
	})

	stream, err := grpc_health_v1.NewHealthClient(cc1).Watch(
		metadata.AppendToOutgoingContext(t.Context(), "TEST_KEY", "TEST_VALUE"),
		&grpc_health_v1.HealthCheckRequest{},
	)
	assert.NoError(t, err)
	res, err := stream.Recv()
	assert.NoError(t, err)
	assert.Empty(t, cmp.Diff(res1, res, protocmp.Transform()))
	_, err = stream.Recv()
	assert.ErrorIs(t, err, io.EOF)

	cc2 := testutil.NewGRPCServer(t, func(s *grpc.Server) {
		f := grpcutil.NewForwarder()
		grpc_health_v1.RegisterHealthServer(s, mockHealthServer{
			watch: func(req *grpc_health_v1.HealthCheckRequest, stream grpc.ServerStreamingServer[grpc_health_v1.HealthCheckResponse]) error {
				return grpcutil.ForwardStream(f, stream, grpc_health_v1.NewHealthClient(cc1).Watch, req)
			},
		})
	})

	stream, err = grpc_health_v1.NewHealthClient(cc2).Watch(
		metadata.AppendToOutgoingContext(t.Context(), "TEST_KEY", "TEST_VALUE"),
		&grpc_health_v1.HealthCheckRequest{},
	)
	assert.NoError(t, err)
	res, err = stream.Recv()
	assert.NoError(t, err)
	assert.Empty(t, cmp.Diff(res1, res, protocmp.Transform()))
	_, err = stream.Recv()
	assert.ErrorIs(t, err, io.EOF)

	t.Run("cycle detection", func(t *testing.T) {
		t.Parallel()

		var ccCycle grpc.ClientConnInterface
		ccCycle = testutil.NewGRPCServer(t, func(s *grpc.Server) {
			f := grpcutil.NewForwarder()
			grpc_health_v1.RegisterHealthServer(s, mockHealthServer{
				watch: func(req *grpc_health_v1.HealthCheckRequest, stream grpc.ServerStreamingServer[grpc_health_v1.HealthCheckResponse]) error {
					return grpcutil.ForwardStream(f, stream, grpc_health_v1.NewHealthClient(ccCycle).Watch, req)
				},
			})
		})

		stream, err := grpc_health_v1.NewHealthClient(ccCycle).Watch(t.Context(), &grpc_health_v1.HealthCheckRequest{})
		assert.NoError(t, err)
		_, err = stream.Recv()
		assert.ErrorIs(t, err, grpcutil.ErrForwardingCycleDetected)
	})
}

func TestForwardUnary(t *testing.T) {
	t.Parallel()

	res1 := &grpc_health_v1.HealthListResponse{
		Statuses: map[string]*grpc_health_v1.HealthCheckResponse{
			"srv1": {
				Status: grpc_health_v1.HealthCheckResponse_SERVING,
			},
		},
	}

	cc1 := testutil.NewGRPCServer(t, func(s *grpc.Server) {
		grpc_health_v1.RegisterHealthServer(s, mockHealthServer{
			list: func(ctx context.Context, _ *grpc_health_v1.HealthListRequest) (*grpc_health_v1.HealthListResponse, error) {
				assert.Equal(t, []string{"TEST_VALUE"}, metadata.ValueFromIncomingContext(ctx, "TEST_KEY"))
				return res1, nil
			},
		})
	})

	res, err := grpc_health_v1.NewHealthClient(cc1).List(
		metadata.AppendToOutgoingContext(t.Context(), "TEST_KEY", "TEST_VALUE"),
		&grpc_health_v1.HealthListRequest{},
	)
	assert.NoError(t, err)
	assert.Empty(t, cmp.Diff(res1, res, protocmp.Transform()))

	cc2 := testutil.NewGRPCServer(t, func(s *grpc.Server) {
		f := grpcutil.NewForwarder()
		grpc_health_v1.RegisterHealthServer(s, mockHealthServer{
			list: func(ctx context.Context, req *grpc_health_v1.HealthListRequest) (*grpc_health_v1.HealthListResponse, error) {
				return grpcutil.ForwardUnary(ctx, f, grpc_health_v1.NewHealthClient(cc1).List, req)
			},
		})
	})

	res, err = grpc_health_v1.NewHealthClient(cc2).List(
		metadata.AppendToOutgoingContext(t.Context(), "TEST_KEY", "TEST_VALUE"),
		&grpc_health_v1.HealthListRequest{},
	)
	assert.NoError(t, err)
	assert.Empty(t, cmp.Diff(res1, res, protocmp.Transform()))

	t.Run("cycle detection", func(t *testing.T) {
		t.Parallel()

		var ccCycle grpc.ClientConnInterface
		ccCycle = testutil.NewGRPCServer(t, func(s *grpc.Server) {
			f := grpcutil.NewForwarder()
			grpc_health_v1.RegisterHealthServer(s, mockHealthServer{
				list: func(ctx context.Context, req *grpc_health_v1.HealthListRequest) (*grpc_health_v1.HealthListResponse, error) {
					return grpcutil.ForwardUnary(ctx, f, grpc_health_v1.NewHealthClient(ccCycle).List, req)
				},
			})
		})

		_, err := grpc_health_v1.NewHealthClient(ccCycle).List(t.Context(), &grpc_health_v1.HealthListRequest{})
		assert.ErrorIs(t, err, grpcutil.ErrForwardingCycleDetected)
	})
}
