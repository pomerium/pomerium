package storage

import (
	"context"
	"strconv"
	"sync"

	"github.com/google/uuid"
	grpc "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

// A Querier is a read-only subset of the client methods
type Querier interface {
	InvalidateCache(ctx context.Context, in *databroker.QueryRequest)
	Query(ctx context.Context, in *databroker.QueryRequest, opts ...grpc.CallOption) (*databroker.QueryResponse, error)
}

// nilQuerier always returns NotFound.
type nilQuerier struct{}

func (nilQuerier) InvalidateCache(ctx context.Context, in *databroker.QueryRequest) {}

func (nilQuerier) Query(ctx context.Context, in *databroker.QueryRequest, opts ...grpc.CallOption) (*databroker.QueryResponse, error) {
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
		any := protoutil.NewAny(msg)
		record := new(databroker.Record)
		record.ModifiedAt = timestamppb.Now()
		record.Version = cryptutil.NewRandomUInt64()
		record.Id = uuid.New().String()
		record.Data = any
		record.Type = any.TypeUrl
		if hasID, ok := msg.(interface{ GetId() string }); ok {
			record.Id = hasID.GetId()
		}
		if hasVersion, ok := msg.(interface{ GetVersion() string }); ok {
			if v, err := strconv.ParseUint(hasVersion.GetVersion(), 10, 64); err == nil {
				record.Version = v
			}
		}
		getter.records = append(getter.records, record)
	}
	return getter
}

func (q *staticQuerier) InvalidateCache(ctx context.Context, in *databroker.QueryRequest) {}

// Query queries for records.
func (q *staticQuerier) Query(ctx context.Context, in *databroker.QueryRequest, opts ...grpc.CallOption) (*databroker.QueryResponse, error) {
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

func (q *clientQuerier) InvalidateCache(ctx context.Context, in *databroker.QueryRequest) {}

// Query queries for records.
func (q *clientQuerier) Query(ctx context.Context, in *databroker.QueryRequest, opts ...grpc.CallOption) (*databroker.QueryResponse, error) {
	return q.client.Query(ctx, in, opts...)
}

// A TracingQuerier records calls to Query.
type TracingQuerier struct {
	underlying Querier

	mu     sync.Mutex
	traces []QueryTrace
}

// A QueryTrace traces a call to Query.
type QueryTrace struct {
	ServerVersion, RecordVersion uint64

	RecordType string
	Query      string
	Filter     *structpb.Struct
}

// NewTracingQuerier creates a new TracingQuerier.
func NewTracingQuerier(q Querier) *TracingQuerier {
	return &TracingQuerier{
		underlying: q,
	}
}

// InvalidateCache invalidates the cache.
func (q *TracingQuerier) InvalidateCache(ctx context.Context, in *databroker.QueryRequest) {
	q.underlying.InvalidateCache(ctx, in)
}

// Query queries for records.
func (q *TracingQuerier) Query(ctx context.Context, in *databroker.QueryRequest, opts ...grpc.CallOption) (*databroker.QueryResponse, error) {
	res, err := q.underlying.Query(ctx, in, opts...)
	if err == nil {
		q.mu.Lock()
		q.traces = append(q.traces, QueryTrace{
			RecordType: in.GetType(),
			Query:      in.GetQuery(),
			Filter:     in.GetFilter(),
		})
		q.mu.Unlock()
	}
	return res, err
}

// Traces returns all the traces.
func (q *TracingQuerier) Traces() []QueryTrace {
	q.mu.Lock()
	traces := make([]QueryTrace, len(q.traces))
	copy(traces, q.traces)
	q.mu.Unlock()
	return traces
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
	key, err := (&proto.MarshalOptions{
		Deterministic: true,
	}).Marshal(in)
	if err != nil {
		return nil, err
	}

	rawResult, err := q.cache.GetOrUpdate(ctx, key, func(ctx context.Context) ([]byte, error) {
		res, err := q.q.Query(ctx, in, opts...)
		if err != nil {
			return nil, err
		}
		return proto.Marshal(res)
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
