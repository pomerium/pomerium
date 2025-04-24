package mcp_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/pomerium/pomerium/internal/databroker"
	"github.com/pomerium/pomerium/internal/mcp"
	oauth21proto "github.com/pomerium/pomerium/internal/oauth21/gen"
	rfc7591v1 "github.com/pomerium/pomerium/internal/rfc7591"
	"github.com/pomerium/pomerium/internal/testutil"
	databroker_grpc "github.com/pomerium/pomerium/pkg/grpc/databroker"
)

func TestStorage(t *testing.T) {
	t.Parallel()

	ctx := testutil.GetContext(t, time.Minute*5)

	list := bufconn.Listen(1024 * 1024)
	t.Cleanup(func() {
		list.Close()
	})

	srv := databroker.New(ctx, noop.NewTracerProvider())
	grpcServer := grpc.NewServer()
	databroker_grpc.RegisterDataBrokerServiceServer(grpcServer, srv)

	go func() {
		if err := grpcServer.Serve(list); err != nil {
			t.Errorf("failed to serve: %v", err)
		}
	}()
	t.Cleanup(func() {
		grpcServer.Stop()
	})

	conn, err := grpc.DialContext(ctx, "bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return list.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)

	client := databroker_grpc.NewDataBrokerServiceClient(conn)
	storage := mcp.NewStorage(client)

	t.Run("client registration", func(t *testing.T) {
		t.Parallel()

		id, err := storage.RegisterClient(ctx, &rfc7591v1.ClientMetadata{})
		require.NoError(t, err)
		require.NotEmpty(t, id)

		_, err = storage.GetClient(ctx, id)
		require.NoError(t, err)
	})

	t.Run("authorization request", func(t *testing.T) {
		t.Parallel()

		id, err := storage.CreateAuthorizationRequest(ctx, &oauth21proto.AuthorizationRequest{})
		require.NoError(t, err)

		_, err = storage.GetAuthorizationRequest(ctx, id)
		require.NoError(t, err)
	})
}
