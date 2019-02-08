package middleware // import "github.com/pomerium/pomerium/internal/middleware"

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// SharedSecretCred is a simple token-based method of mutual authentication.
type SharedSecretCred struct{ sharedSecret string }

// NewSharedSecretCred returns a new instance of shared secret credential middleware for gRPC clients
func NewSharedSecretCred(secret string) *SharedSecretCred {
	return &SharedSecretCred{sharedSecret: secret}
}

// GetRequestMetadata sets the value for "authorization" key
func (s SharedSecretCred) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	return map[string]string{"authorization": s.sharedSecret}, nil
}

// RequireTransportSecurity should be true as we want to have it encrypted over the wire.
func (s SharedSecretCred) RequireTransportSecurity() bool { return false }

// ValidateRequest ensures a valid token exists within a request's metadata. If
// the token is missing or invalid, the interceptor blocks execution of the
// handler and returns an error. Otherwise, the interceptor invokes the unary
// handler.
func (s SharedSecretCred) ValidateRequest(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Errorf(codes.InvalidArgument, "missing metadata")
	}
	// The keys within metadata.MD are normalized to lowercase.
	// See: https://godoc.org/google.golang.org/grpc/metadata#New
	elem, ok := md["authorization"]
	if !ok {
		return nil, status.Errorf(codes.InvalidArgument, "no auth details supplied")
	}
	if elem[0] != s.sharedSecret {
		return nil, status.Errorf(codes.Unauthenticated, "invalid shared secrets")
	}
	// Continue execution of handler after ensuring a valid token.
	return handler(ctx, req)
}
