package grpcutil_test

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"

	"github.com/pomerium/pomerium/pkg/grpcutil"
)

type testHealthServer struct {
	check func(ctx context.Context, req *grpc_health_v1.HealthCheckRequest) (*grpc_health_v1.HealthCheckResponse, error)
	grpc_health_v1.UnimplementedHealthServer
}

func (s testHealthServer) Check(ctx context.Context, req *grpc_health_v1.HealthCheckRequest) (*grpc_health_v1.HealthCheckResponse, error) {
	return s.check(ctx, req)
}

func TestErrors(t *testing.T) {
	t.Parallel()

	li, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = li.Close() })

	var checkErr error

	s := grpc.NewServer()
	grpc_health_v1.RegisterHealthServer(s, testHealthServer{
		check: func(_ context.Context, _ *grpc_health_v1.HealthCheckRequest) (*grpc_health_v1.HealthCheckResponse, error) {
			return nil, checkErr
		},
	})
	go s.Serve(li)

	cc, err := grpc.NewClient(li.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	c := grpc_health_v1.NewHealthClient(cc)

	for _, tc := range []struct {
		err1, err2 error
		matches    bool
	}{
		{
			grpcutil.NewError(codes.DataLoss, "A", "message 1"),
			grpcutil.NewError(codes.DataLoss, "A", "message 1"),
			true,
		},
		{
			grpcutil.NewError(codes.DataLoss, "A", "message 1"),
			must(status.New(codes.DataLoss, "A: message 1").WithDetails(&errdetails.ErrorInfo{
				Domain: "pomerium.com",
				Reason: "A",
			})).Err(),
			true,
		},
		{
			grpcutil.NewError(codes.DataLoss, "A", "message 1"),
			grpcutil.NewError(codes.DataLoss, "A", "message 2"),
			false,
		},
		{
			grpcutil.NewError(codes.DataLoss, "A", "message 1", "a", "b"),
			grpcutil.NewError(codes.DataLoss, "A", "message 1", "x", "y"),
			false,
		},
		{
			grpcutil.NewError(codes.NotFound, "A", "message 1"),
			grpcutil.NewError(codes.DataLoss, "A", "message 1"),
			false,
		},
		{
			grpcutil.NewError(codes.DataLoss, "A", "message 1"),
			grpcutil.NewError(codes.DataLoss, "B", "message 1"),
			false,
		},
	} {
		checkErr = tc.err1
		_, err = c.Check(t.Context(), new(grpc_health_v1.HealthCheckRequest))
		if tc.matches {
			assert.ErrorIs(t, err, tc.err2, "errors should be equal")
		} else {
			assert.NotErrorIs(t, err, tc.err2, "errors should not be equal")
		}
	}
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
