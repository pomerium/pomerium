package storage

import (
	"context"
	"encoding/json"
	"errors"

	grpc "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpcutil"
)

// ErrUnavailable indicates that a querier is not available.
var ErrUnavailable = errors.New("unavailable")

// A Querier is a read-only subset of the client methods
type Querier interface {
	InvalidateCache(ctx context.Context, in *databroker.QueryRequest)
	Query(ctx context.Context, in *databroker.QueryRequest, opts ...grpc.CallOption) (*databroker.QueryResponse, error)
	Stop()
}

// nilQuerier always returns NotFound.
type nilQuerier struct{}

func (nilQuerier) InvalidateCache(_ context.Context, _ *databroker.QueryRequest) {}

func (nilQuerier) Query(_ context.Context, _ *databroker.QueryRequest, _ ...grpc.CallOption) (*databroker.QueryResponse, error) {
	return nil, errors.Join(ErrUnavailable, status.Error(codes.NotFound, "not found"))
}

func (nilQuerier) Stop() {}

type querierKey struct{}

// GetQuerier gets the databroker Querier from the context.
func GetQuerier(ctx context.Context) Querier {
	q, ok := ctx.Value(querierKey{}).(Querier)
	if !ok {
		q = nilQuerier{}
	}
	return q
}

// WithQuerier sets the databroker Querier on a context.
func WithQuerier(ctx context.Context, querier Querier) context.Context {
	return context.WithValue(ctx, querierKey{}, querier)
}

// MarshalQueryRequest marshales the query request.
func MarshalQueryRequest(req *databroker.QueryRequest) ([]byte, error) {
	return (&proto.MarshalOptions{
		Deterministic: true,
	}).Marshal(req)
}

// MarshalQueryResponse marshals the query response.
func MarshalQueryResponse(res *databroker.QueryResponse) ([]byte, error) {
	return (&proto.MarshalOptions{
		Deterministic: true,
	}).Marshal(res)
}

// GetDataBrokerRecord uses a querier to get a databroker record.
func GetDataBrokerRecord(
	ctx context.Context,
	recordType string,
	recordID string,
	lowestRecordVersion uint64,
) (*databroker.Record, error) {
	q := GetQuerier(ctx)

	req := &databroker.QueryRequest{
		Type:  recordType,
		Limit: 1,
	}
	if lowestRecordVersion > 0 {
		req.MinimumRecordVersionHint = proto.Uint64(lowestRecordVersion)
	}
	req.SetFilterByIDOrIndex(recordID)

	res, err := q.Query(ctx, req, grpc.WaitForReady(true))
	if err != nil {
		return nil, err
	}
	if len(res.GetRecords()) == 0 {
		return nil, ErrNotFound
	}
	return res.GetRecords()[0], nil
}

// GetDataBrokerMessage gets a databroker record and converts it into the message type.
func GetDataBrokerMessage[T any, TMessage interface {
	*T
	proto.Message
}](
	ctx context.Context,
	recordID string,
	lowestRecordVersion uint64,
) (TMessage, error) {
	var msg T

	record, err := GetDataBrokerRecord(ctx, grpcutil.GetTypeURL(TMessage(&msg)), recordID, lowestRecordVersion)
	if err != nil {
		return nil, err
	}

	err = record.GetData().UnmarshalTo(TMessage(&msg))
	if err != nil {
		return nil, err
	}

	return TMessage(&msg), nil
}

// GetDataBrokerObjectViaJSON gets a databroker record and converts it into the object type by going through protojson.
func GetDataBrokerObjectViaJSON[T any](
	ctx context.Context,
	recordType string,
	recordID string,
	lowestRecordVersion uint64,
) (*T, error) {
	record, err := GetDataBrokerRecord(ctx, recordType, recordID, lowestRecordVersion)
	if err != nil {
		return nil, err
	}

	msg, err := record.GetData().UnmarshalNew()
	if err != nil {
		return nil, err
	}

	bs, err := protojson.Marshal(msg)
	if err != nil {
		return nil, err
	}

	var obj T
	err = json.Unmarshal(bs, &obj)
	if err != nil {
		return nil, err
	}
	return &obj, nil
}

// InvalidateCacheForDataBrokerRecords invalidates the cache of the querier for the databroker records.
func InvalidateCacheForDataBrokerRecords(
	ctx context.Context,
	records ...*databroker.Record,
) {
	for _, record := range records {
		q := &databroker.QueryRequest{
			Type:  record.GetType(),
			Limit: 1,
		}
		q.SetFilterByIDOrIndex(record.GetId())
		GetQuerier(ctx).InvalidateCache(ctx, q)
	}
}
