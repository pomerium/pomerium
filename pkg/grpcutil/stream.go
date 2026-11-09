package grpcutil

import (
	"context"

	"google.golang.org/grpc"

	"github.com/pomerium/pomerium/pkg/contextutil"
)

type serverStreamingServerWithContext[Res any] struct {
	ctx context.Context
	grpc.ServerStreamingServer[Res]
}

func (s *serverStreamingServerWithContext[Res]) Send(res *Res) error {
	// return immediately if the context is already done
	select {
	case <-s.ctx.Done():
		return context.Cause(s.ctx)
	default:
	}

	errc := make(chan error, 1)
	go func() { errc <- s.ServerStreamingServer.Send(res) }()
	select {
	case <-s.ctx.Done():
		return context.Cause(s.ctx)
	case err := <-errc:
		return err
	}
}

func (s *serverStreamingServerWithContext[Res]) Context() context.Context {
	return s.ctx
}

// HandleServerStreamingServerWithContext calls a function with a wrapped
// gRPC ServerStreamingServer with a merged context so anything using that
// stream can be canceled if either the stream context or the parent context
// are canceled.
func HandleServerStreamingServerWithContext[Res any](
	ctx context.Context,
	stream grpc.ServerStreamingServer[Res],
	fn func(stream grpc.ServerStreamingServer[Res]) error,
) error {
	ctx, cancel := contextutil.Merge(ctx, stream.Context())
	defer cancel(nil)
	return fn(&serverStreamingServerWithContext[Res]{
		ctx:                   ctx,
		ServerStreamingServer: stream,
	})
}
