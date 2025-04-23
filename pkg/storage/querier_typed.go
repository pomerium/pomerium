package storage

import (
	"context"

	grpc "google.golang.org/grpc"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

type typedQuerier struct {
	defaultQuerier Querier
	queriersByType map[string]Querier
}

// NewTypedQuerier creates a new Querier that dispatches to other queries based on the type.
func NewTypedQuerier(defaultQuerier Querier, queriersByType map[string]Querier) Querier {
	return &typedQuerier{
		defaultQuerier: defaultQuerier,
		queriersByType: queriersByType,
	}
}

func (q *typedQuerier) InvalidateCache(ctx context.Context, req *databroker.QueryRequest) {
	qq, ok := q.queriersByType[req.Type]
	if !ok {
		qq = q.defaultQuerier
	}
	qq.InvalidateCache(ctx, req)
}

func (q *typedQuerier) Query(ctx context.Context, req *databroker.QueryRequest, opts ...grpc.CallOption) (*databroker.QueryResponse, error) {
	qq, ok := q.queriersByType[req.Type]
	if !ok {
		qq = q.defaultQuerier
	}
	return qq.Query(ctx, req, opts...)
}

func (q *typedQuerier) Stop() {
	q.defaultQuerier.Stop()
	for _, qq := range q.queriersByType {
		qq.Stop()
	}
}
