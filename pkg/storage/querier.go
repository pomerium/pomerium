package storage

import (
	"context"
	"encoding/json"
	"strconv"

	"github.com/google/uuid"
	grpc "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpcutil"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

// A Querier is a read-only subset of the client methods
type Querier interface {
	InvalidateCache(ctx context.Context, in *databroker.QueryRequest)
	Query(ctx context.Context, in *databroker.QueryRequest, opts ...grpc.CallOption) (*databroker.QueryResponse, error)
}

// nilQuerier always returns NotFound.
type nilQuerier struct{}

func (nilQuerier) InvalidateCache(_ context.Context, _ *databroker.QueryRequest) {}

func (nilQuerier) Query(_ context.Context, _ *databroker.QueryRequest, _ ...grpc.CallOption) (*databroker.QueryResponse, error) {
	return nil, status.Error(codes.NotFound, "not found")
}

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

type staticQuerier struct {
	records []*databroker.Record
}

// NewStaticQuerier creates a Querier that returns statically defined protobuf records.
func NewStaticQuerier(msgs ...proto.Message) Querier {
	getter := &staticQuerier{}
	for _, msg := range msgs {
		record, ok := msg.(*databroker.Record)
		if !ok {
			record = NewStaticRecord(protoutil.NewAny(msg).TypeUrl, msg)
		}
		getter.records = append(getter.records, record)
	}
	return getter
}

// NewStaticRecord creates a new databroker Record from a protobuf message.
func NewStaticRecord(typeURL string, msg proto.Message) *databroker.Record {
	data := protoutil.NewAny(msg)
	record := new(databroker.Record)
	record.ModifiedAt = timestamppb.Now()
	record.Version = cryptutil.NewRandomUInt64()
	record.Id = uuid.New().String()
	record.Data = data
	record.Type = typeURL
	if hasID, ok := msg.(interface{ GetId() string }); ok {
		record.Id = hasID.GetId()
	}
	if hasVersion, ok := msg.(interface{ GetVersion() string }); ok {
		if v, err := strconv.ParseUint(hasVersion.GetVersion(), 10, 64); err == nil {
			record.Version = v
		}
	}

	var jsonData struct {
		ID      string `json:"id"`
		Version string `json:"version"`
	}
	bs, _ := protojson.Marshal(msg)
	_ = json.Unmarshal(bs, &jsonData)

	if jsonData.ID != "" {
		record.Id = jsonData.ID
	}
	if jsonData.Version != "" {
		if v, err := strconv.ParseUint(jsonData.Version, 10, 64); err == nil {
			record.Version = v
		}
	}

	return record
}

func (q *staticQuerier) InvalidateCache(_ context.Context, _ *databroker.QueryRequest) {}

// Query queries for records.
func (q *staticQuerier) Query(_ context.Context, in *databroker.QueryRequest, _ ...grpc.CallOption) (*databroker.QueryResponse, error) {
	expr, err := FilterExpressionFromStruct(in.GetFilter())
	if err != nil {
		return nil, err
	}

	filter, err := RecordStreamFilterFromFilterExpression(expr)
	if err != nil {
		return nil, err
	}

	res := new(databroker.QueryResponse)
	for _, record := range q.records {
		if record.GetType() != in.GetType() {
			continue
		}

		if !filter(record) {
			continue
		}

		if in.GetQuery() != "" && !MatchAny(record.GetData(), in.GetQuery()) {
			continue
		}

		res.Records = append(res.Records, record)
	}

	var total int
	res.Records, total = databroker.ApplyOffsetAndLimit(
		res.Records,
		int(in.GetOffset()),
		int(in.GetLimit()),
	)
	res.TotalCount = int64(total)
	return res, nil
}

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

type cachingQuerier struct {
	q     Querier
	cache Cache
}

// NewCachingQuerier creates a new querier that caches results in a Cache.
func NewCachingQuerier(q Querier, cache Cache) Querier {
	return &cachingQuerier{
		q:     q,
		cache: cache,
	}
}

func (q *cachingQuerier) InvalidateCache(ctx context.Context, in *databroker.QueryRequest) {
	key, err := (&proto.MarshalOptions{
		Deterministic: true,
	}).Marshal(in)
	if err != nil {
		return
	}
	q.cache.Invalidate(key)
	q.q.InvalidateCache(ctx, in)
}

func (q *cachingQuerier) Query(ctx context.Context, in *databroker.QueryRequest, opts ...grpc.CallOption) (*databroker.QueryResponse, error) {
	key, err := MarshalQueryRequest(in)
	if err != nil {
		return nil, err
	}

	rawResult, err := q.cache.GetOrUpdate(ctx, key, func(ctx context.Context) ([]byte, error) {
		res, err := q.q.Query(ctx, in, opts...)
		if err != nil {
			return nil, err
		}
		return MarshalQueryResponse(res)
	})
	if err != nil {
		return nil, err
	}

	var res databroker.QueryResponse
	err = proto.Unmarshal(rawResult, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
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
	req.SetFilterByIDOrIndex(recordID)

	res, err := q.Query(ctx, req, grpc.WaitForReady(true))
	if err != nil {
		return nil, err
	}
	if len(res.GetRecords()) == 0 {
		return nil, ErrNotFound
	}

	// if the current record version is less than the lowest we'll accept, invalidate the cache
	if res.GetRecords()[0].GetVersion() < lowestRecordVersion {
		q.InvalidateCache(ctx, req)
	} else {
		return res.GetRecords()[0], nil
	}

	// retry with an up to date cache
	res, err = q.Query(ctx, req)
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
