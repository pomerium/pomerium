package testutil

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc"

	"github.com/pomerium/pomerium/internal/databroker"
	"github.com/pomerium/pomerium/internal/testutil"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
)

func NewTestDatabroker(t *testing.T) databrokerpb.DataBrokerServiceClient {
	t.Helper()

	srv := databroker.NewBackendServer(noop.NewTracerProvider())
	t.Cleanup(srv.Stop)

	cc := testutil.NewGRPCServer(t, func(s *grpc.Server) {
		databrokerpb.RegisterDataBrokerServiceServer(s, srv)
	})
	t.Cleanup(func() { cc.Close() })

	return databrokerpb.NewDataBrokerServiceClient(cc)
}

// FailingDatabroker wraps a client so the operations a caller makes fail with
// err, letting a test inject an infrastructure failure without a broken
// databroker. Only the calls that go through the transaction stream and the
// unary Get are overridden; everything else is served by the wrapped client.
func FailingDatabroker(client databrokerpb.DataBrokerServiceClient, err error) databrokerpb.DataBrokerServiceClient {
	return failingDatabroker{DataBrokerServiceClient: client, err: err}
}

type failingDatabroker struct {
	databrokerpb.DataBrokerServiceClient
	err error
}

func (c failingDatabroker) Get(
	context.Context, *databrokerpb.GetRequest, ...grpc.CallOption,
) (*databrokerpb.GetResponse, error) {
	return nil, c.err
}

func (c failingDatabroker) Transaction(
	context.Context, ...grpc.CallOption,
) (grpc.BidiStreamingClient[databrokerpb.TransactionStreamRequest, databrokerpb.TransactionStreamResponse], error) {
	return nil, c.err
}
