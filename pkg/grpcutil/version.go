package grpcutil

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// MetadataKeyEnvoyVersion is the gRPC metadata key used for the envoy version.
const MetadataKeyEnvoyVersion = "x-envoy-version"

// MetadataKeyPomeriumVersion is the gRPC metadata key used for the pomerium version.
const MetadataKeyPomeriumVersion = "x-pomerium-version"

// AttachMetadataInterceptors returns unary and server stream interceptors that attach metadata to the response.
func AttachMetadataInterceptors(md metadata.MD) (grpc.UnaryServerInterceptor, grpc.StreamServerInterceptor) {
	unary := func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
		_ = grpc.SetHeader(ctx, md)
		return handler(ctx, req)
	}

	stream := func(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		_ = ss.SetHeader(md)
		return handler(srv, ss)
	}

	return unary, stream
}
