package storage

import (
	"context"

	grpc "google.golang.org/grpc"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

type clientQuerier struct {
	client databroker.DataBrokerServiceClient
}

// NewQuerier creates a new Querier that implements the Querier interface by making calls to the databroker over gRPC.
func NewQuerier(client databroker.DataBrokerServiceClient) Querier {
	return &clientQuerier{client: client}
}

func (q *clientQuerier) InvalidateCache(_ context.Context, _ *databroker.QueryRequest) {}

// Query queries for records.
func (q *clientQuerier) Query(ctx context.Context, in *databroker.QueryRequest, opts ...grpc.CallOption) (*databroker.QueryResponse, error) {
	return q.client.Query(ctx, in, opts...)
}

func (*clientQuerier) Stop() {}
