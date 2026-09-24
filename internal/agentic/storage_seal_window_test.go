package agentic

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/timestamppb"

	agenticpb "github.com/pomerium/pomerium/internal/agentic/gen"
	"github.com/pomerium/pomerium/internal/databroker"
	databroker_grpc "github.com/pomerium/pomerium/pkg/grpc/databroker"
)

// newSealWindowDataBroker is a databroker backed by an in-process server, with
// the agentic.Run secondary index registered — the seal lookup is a query against
// that index, so an in-memory fake would not exercise it.
func newSealWindowDataBroker(ctx context.Context, t *testing.T) databroker_grpc.DataBrokerServiceClient {
	t.Helper()

	list := bufconn.Listen(1024 * 1024)
	t.Cleanup(func() { list.Close() })

	srv := databroker.NewBackendServer(noop.NewTracerProvider())
	t.Cleanup(srv.Stop)
	grpcServer := grpc.NewServer()
	databroker_grpc.RegisterDataBrokerServiceServer(grpcServer, srv)
	go func() {
		if err := grpcServer.Serve(list); err != nil {
			t.Errorf("failed to serve: %v", err)
		}
	}()
	t.Cleanup(grpcServer.Stop)

	conn, err := grpc.DialContext(ctx, "bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return list.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)

	return databroker_grpc.NewDataBrokerServiceClient(conn)
}

// TestQueryRunByBoundClaimsIndexFindsApprovedBeyondAPage seeds more runs for one
// executor than a page-sized window would cover, with the approved one created
// last, and requires the lookup to still resolve it.
//
// The databroker applies Limit before QueryRunByBoundClaimsIndex ranks the
// candidates, so a window that does not cover every record can return a pending
// run while an approved one exists — the approval then becomes permanently
// unreachable through the run_id-less exchange.
func TestQueryRunByBoundClaimsIndexFindsApprovedBeyondAPage(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client := newSealWindowDataBroker(ctx, t)

	const idx = "kubernetes.io.namespace=%22default%22"
	const pending = 24

	for i := range pending {
		require.NoError(t, PutRun(ctx, client, &agenticpb.Run{
			Id:               fmt.Sprintf("run-pending-%02d", i),
			BoundClaimsIndex: idx,
			State:            agenticpb.RunState_RUN_STATE_PENDING,
			ExpiresAt:        timestamppb.New(time.Now().Add(time.Hour)),
		}))
	}
	approved := &agenticpb.Run{
		Id:               "run-zz-approved",
		BoundClaimsIndex: idx,
		State:            agenticpb.RunState_RUN_STATE_APPROVED,
		Sub:              "alice@example.com",
		ExpiresAt:        timestamppb.New(time.Now().Add(time.Hour)),
	}
	require.NoError(t, PutRun(ctx, client, approved))

	got, err := QueryRunByBoundClaimsIndex(ctx, client, idx)
	require.NoError(t, err)
	require.NotNil(t, got, "the executor has runs, so the lookup must resolve one")
	assert.Equal(t, approved.GetId(), got.GetId(),
		"an approved run must win over pending ones regardless of how many exist")
	assert.Equal(t, agenticpb.RunState_RUN_STATE_APPROVED, got.GetState())
}
