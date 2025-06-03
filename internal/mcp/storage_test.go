package mcp_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"

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

	t.Run("upstream oauth2 token", func(t *testing.T) {
		t.Parallel()

		want := &oauth21proto.TokenResponse{
			AccessToken:  "access-token",
			TokenType:    "token-type",
			ExpiresIn:    proto.Int64(3600),
			RefreshToken: proto.String("refresh-token"),
			Scope:        proto.String("scope"),
		}
		err := storage.StoreUpstreamOAuth2Token(ctx, "host", "user-id", want)
		require.NoError(t, err)

		got, err := storage.GetUpstreamOAuth2Token(ctx, "host", "user-id")
		require.NoError(t, err)
		require.Empty(t, cmp.Diff(want, got, protocmp.Transform()))

		_, err = storage.GetUpstreamOAuth2Token(ctx, "non-existent-host", "user-id")
		assert.Equal(t, codes.NotFound, status.Code(err))

		_, err = storage.GetUpstreamOAuth2Token(ctx, "host", "non-existent-user-id")
		assert.Equal(t, codes.NotFound, status.Code(err))
	})
}
