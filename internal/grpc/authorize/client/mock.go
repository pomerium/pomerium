package client

import (
	"context"
	"net/http"
)

var _ Authorizer = &MockAuthorize{}

// MockAuthorize provides a mocked implementation of the authorizer interface.
type MockAuthorize struct {
	AuthorizeResponse bool
	AuthorizeError    error
	IsAdminResponse   bool
	IsAdminError      error
	CloseError        error
}

// Close is a mocked authorizer client function.
func (a MockAuthorize) Close() error { return a.CloseError }

// Authorize is a mocked authorizer client function.
func (a MockAuthorize) Authorize(ctx context.Context, user string, s *http.Request) (bool, error) {
	return a.AuthorizeResponse, a.AuthorizeError
}

// IsAdmin is a mocked IsAdmin function.
func (a MockAuthorize) IsAdmin(ctx context.Context, user string) (bool, error) {
	return a.IsAdminResponse, a.IsAdminError
}
