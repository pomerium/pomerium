package databrokerutil

import (
	"context"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

type Result struct {
	Val    any
	Err    error
	Shared bool
}

type SingleFlight struct {
	client databroker.ClientGetter
}

func (s *SingleFlight) Do(ctx context.Context, key string, fn func() (any, error)) (v any, err error, shared bool) {
	panic("implement me")
}

func (s *SingleFlight) DoChan(ctx context.Context, key string, fn func() (any, error)) <-chan Result {
	panic("implement me")
}
