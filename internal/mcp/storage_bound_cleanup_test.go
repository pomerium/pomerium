package mcp_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/databroker"
	"github.com/pomerium/pomerium/internal/mcp"
	databroker_grpc "github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/idpsession"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

// cancelOnIDPSessionGetClient models the MCP client giving up on the token
// request (its HTTP context is cancelled) right after PutBoundSession's write
// landed, while the re-read of the IDPSession is in flight.
type cancelOnIDPSessionGetClient struct {
	databroker_grpc.DataBrokerServiceClient
	cancel context.CancelFunc
}

func (c *cancelOnIDPSessionGetClient) Get(ctx context.Context, req *databroker_grpc.GetRequest, opts ...grpc.CallOption) (*databroker_grpc.GetResponse, error) {
	if req.GetType() == protoutil.GetTypeURL(new(idpsession.IDPSession)) {
		c.cancel()
		return nil, status.FromContextError(context.Canceled).Err()
	}
	return c.DataBrokerServiceClient.Get(ctx, req, opts...)
}

// PutBoundSession promises that a session bound to an IDPSession it could not
// confirm is removed again. The removal runs on the request context, so when the
// confirmation failed because that context was cancelled the removal fails too
// (it is only logged), and the session (holding the user's upstream tokens) and
// its MCP binding stay behind. Here the IDPSession is also gone (sign-out raced
// the exchange), so per PutBoundSession's own doc comment the identity manager
// will never revoke that binding.
func TestPutBoundSessionCleanupSurvivesCancelledRequest(t *testing.T) {
	ctx := t.Context()

	list := bufconn.Listen(1024 * 1024)
	t.Cleanup(func() { list.Close() })
	srv := databroker.NewBackendServer(noop.NewTracerProvider())
	t.Cleanup(srv.Stop)
	grpcServer := grpc.NewServer()
	databroker_grpc.RegisterDataBrokerServiceServer(grpcServer, srv)
	go func() { _ = grpcServer.Serve(list) }()
	t.Cleanup(grpcServer.Stop)
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return list.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	client := databroker_grpc.NewDataBrokerServiceClient(conn)

	reqCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	storage := mcp.NewStorage(databroker_grpc.NewStaticClientGetter(
		&cancelOnIDPSessionGetClient{DataBrokerServiceClient: client, cancel: cancel}))

	sess := &session.Session{
		Id:        "orphan-candidate",
		UserId:    "user-1",
		IssuedAt:  timestamppb.Now(),
		ExpiresAt: timestamppb.New(time.Now().Add(365 * 24 * time.Hour)),
		OauthToken: &session.OAuthToken{
			RefreshToken: "upstream-refresh-token",
		},
	}
	_, err = storage.PutBoundSession(reqCtx, sess, "signed-out-idp-session", nil)
	require.Error(t, err)

	verify := mcp.NewStorage(databroker_grpc.NewStaticClientGetter(client))
	_, _, err = verify.GetSession(ctx, sess.GetId())
	assert.Equal(t, codes.NotFound, status.Code(err),
		"a session PutBoundSession reported as failed must not stay behind: %v", err)
	_, err = verify.GetActiveBinding(ctx, sess.GetId())
	assert.Equal(t, codes.NotFound, status.Code(err),
		"its binding must not stay behind either: %v", err)
}
