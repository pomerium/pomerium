package testutil

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

// NewGRPCServer starts a gRPC server and returns a client connection to it.
func NewGRPCServer(
	t testing.TB,
	register func(s *grpc.Server),
	dialOpts ...grpc.DialOption,
) *grpc.ClientConn {
	t.Helper()

	li := bufconn.Listen(1024 * 1024)
	s := grpc.NewServer()
	register(s)
	go func() {
		err := s.Serve(li)
		if errors.Is(err, grpc.ErrServerStopped) {
			err = nil
		}
		require.NoError(t, err)
	}()
	t.Cleanup(func() {
		s.Stop()
	})

	opts := []grpc.DialOption{
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return li.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	}
	opts = append(opts, dialOpts...)

	cc, err := grpc.NewClient("passthrough://bufnet", opts...)
	require.NoError(t, err)
	t.Cleanup(func() {
		cc.Close()
	})

	return cc
}
