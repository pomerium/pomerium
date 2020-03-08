package client

import (
	"context"
	"net/http"

	pb "github.com/pomerium/pomerium/internal/grpc/authorize"
)

var _ Authorizer = &MockAuthorize{}

// MockAuthorize provides a mocked implementation of the authorizer interface.
type MockAuthorize struct {
	AuthorizeResponse *pb.IsAuthorizedReply
	AuthorizeError    error
	IsAdminResponse   bool
	IsAdminError      error
	CloseError        error
}

// Close is a mocked authorizer client function.
func (a MockAuthorize) Close() error { return a.CloseError }

// Authorize is a mocked authorizer client function.
func (a MockAuthorize) Authorize(ctx context.Context, user string, r *http.Request) (*pb.IsAuthorizedReply, error) {
	return a.AuthorizeResponse, a.AuthorizeError
}
