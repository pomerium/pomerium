package storage

import (
	"context"
	"fmt"

	grpc "google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"

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

// DeleteDataBrokerRecord deletes a databroker record from the databroker and invalidates any cache.
// It returns the record. If the record does not exist nil, nil is returned.
func DeleteDataBrokerRecord(
	ctx context.Context,
	client databroker.DataBrokerServiceClient,
	recordType, recordID string,
) (*databroker.Record, error) {
	res, err := client.Get(ctx, &databroker.GetRequest{
		Type: recordType,
		Id:   recordID,
	})
	if IsNotFound(err) {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("error getting record from databroker for deletion: %w", err)
	}

	record := res.GetRecord()
	record.DeletedAt = timestamppb.Now()

	_, err = client.Put(ctx, &databroker.PutRequest{
		Records: []*databroker.Record{record},
	})
	if err != nil {
		return nil, fmt.Errorf("error deleting record from databroker: %w", err)
	}

	// clear the cache of any querier associated with the context
	InvalidateCacheForDataBrokerRecords(ctx, record)

	// also clear the global cache even if its not being used
	InvalidateCacheForDataBrokerRecords(WithQuerier(ctx, NewCachingQuerier(nilQuerier{}, GlobalCache)), record)

	return record, nil
}
