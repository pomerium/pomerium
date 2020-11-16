package grpcutil

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// MetadataKeyPomeriumVersion is the gRPC metadata key used for the pomerium version.
const MetadataKeyPomeriumVersion = "x-pomerium-version"

// AttachMetadataInterceptors returns unary and server stream interceptors that attach metadata to the response.
func AttachMetadataInterceptors(md metadata.MD) (grpc.UnaryServerInterceptor, grpc.StreamServerInterceptor) {
	unary := func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
		grpc.SetHeader(ctx, md)
		return handler(ctx, req)
	}

	stream := func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ss.SetHeader(md)
		return handler(srv, ss)
	}

	return unary, stream
}
