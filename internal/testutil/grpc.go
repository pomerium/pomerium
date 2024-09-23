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
func NewGRPCServer(t testing.TB, register func(s *grpc.Server)) *grpc.ClientConn {
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

	cc, err := grpc.NewClient("passthrough://bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return li.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() {
		cc.Close()
	})

	return cc
}
