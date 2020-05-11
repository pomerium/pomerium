package requestid

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// StreamClientInterceptor returns a new gRPC StreamClientInterceptor which puts the request ID in the outgoing
// metadata.
func StreamClientInterceptor() grpc.StreamClientInterceptor {
	return func(ctx context.Context,
		desc *grpc.StreamDesc, cc *grpc.ClientConn,
		method string, streamer grpc.Streamer, opts ...grpc.CallOption,
	) (grpc.ClientStream, error) {
		toMetadata(ctx)
		return streamer(ctx, desc, cc, method, opts...)
	}
}

// UnaryClientInterceptor returns a new gRPC UnaryClientInterceptor which puts the request ID in the outgoing
// metadata.
func UnaryClientInterceptor() grpc.UnaryClientInterceptor {
	return func(ctx context.Context,
		method string, req, reply interface{},
		cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption,
	) error {
		toMetadata(ctx)
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

func toMetadata(ctx context.Context) {
	requestID := FromContext(ctx)
	if requestID == "" {
		requestID = New()
	}

	md, ok := metadata.FromOutgoingContext(ctx)
	if !ok {
		return
	}

	md.Set(headerName, requestID)
}
