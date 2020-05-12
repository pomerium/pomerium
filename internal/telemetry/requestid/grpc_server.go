package requestid

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

type grpcStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (ss grpcStream) Context() context.Context {
	return ss.ctx
}

// StreamServerInterceptor returns a new gRPC StreamServerInterceptor which populates the request id
// from the incoming metadata.
func StreamServerInterceptor() grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctx := ss.Context()
		requestID := fromMetadata(ctx)
		ctx = WithValue(ctx, requestID)
		ss = grpcStream{
			ServerStream: ss,
			ctx:          ctx,
		}
		return handler(srv, ss)
	}
}

// UnaryServerInterceptor returns a new gRPC UnaryServerInterceptor which populates the request id
// from the incoming metadata.
func UnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
		requestID := fromMetadata(ctx)
		ctx = WithValue(ctx, requestID)
		return handler(ctx, req)
	}
}

func fromMetadata(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return New()
	}

	headers := md.Get(headerName)
	if len(headers) == 0 || headers[0] == "" {
		return New()
	}

	return headers[0]
}
