package storage

import (
	"context"

	grpc "google.golang.org/grpc"
	"google.golang.org/protobuf/proto"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

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
	key, err := q.getCacheKey(in)
	if err != nil {
		return
	}
	q.cache.Invalidate(key)
	q.q.InvalidateCache(ctx, in)
}

func (q *cachingQuerier) Query(ctx context.Context, in *databroker.QueryRequest, opts ...grpc.CallOption) (*databroker.QueryResponse, error) {
	res, err := q.query(ctx, in, opts...)
	if err != nil {
		return nil, err
	}

	// If a minimum record version hint is sent, check to see if the result meets the minimum
	// record version and if not, invalidate the cache and re-query.
	if in.MinimumRecordVersionHint != nil && res.RecordVersion < *in.MinimumRecordVersionHint {
		q.InvalidateCache(ctx, in)
		res, err = q.query(ctx, in, opts...)
		if err != nil {
			return nil, err
		}
	}

	return res, nil
}

func (q *cachingQuerier) getCacheKey(in *databroker.QueryRequest) ([]byte, error) {
	in = proto.Clone(in).(*databroker.QueryRequest)
	in.MinimumRecordVersionHint = nil
	return MarshalQueryRequest(in)
}

func (q *cachingQuerier) query(ctx context.Context, in *databroker.QueryRequest, opts ...grpc.CallOption) (*databroker.QueryResponse, error) {
	key, err := q.getCacheKey(in)
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
