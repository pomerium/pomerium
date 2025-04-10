package storage

import (
	"context"
	"errors"

	grpc "google.golang.org/grpc"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

type fallbackQuerier []Querier

// NewFallbackQuerier creates a new fallback-querier. The first call to Query that
// does not return an error will be used.
func NewFallbackQuerier(queriers ...Querier) Querier {
	return fallbackQuerier(queriers)
}

// InvalidateCache invalidates the cache of all the queriers.
func (q fallbackQuerier) InvalidateCache(ctx context.Context, req *databroker.QueryRequest) {
	for _, qq := range q {
		qq.InvalidateCache(ctx, req)
	}
}

// Query returns the first querier's results that doesn't result in an error.
func (q fallbackQuerier) Query(ctx context.Context, req *databroker.QueryRequest, opts ...grpc.CallOption) (*databroker.QueryResponse, error) {
	if len(q) == 0 {
		return nil, ErrUnavailable
	}

	var merr error
	for _, qq := range q {
		res, err := qq.Query(ctx, req, opts...)
		if err == nil {
			return res, nil
		}
		merr = errors.Join(merr, err)
	}
	return nil, merr
}

// Stop stops all the queriers.
func (q fallbackQuerier) Stop() {
	for _, qq := range q {
		qq.Stop()
	}
}
