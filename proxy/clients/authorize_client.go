package clients // import "github.com/pomerium/pomerium/proxy/clients"

import (
	"context"
	"errors"
	"time"

	"google.golang.org/grpc"

	"github.com/pomerium/pomerium/internal/sessions"
	pb "github.com/pomerium/pomerium/proto/authorize"
)

// Authorizer provides the authorize service interface
type Authorizer interface {
	// Authorize takes a code and returns a validated session or an error
	Authorize(context.Context, string, *sessions.SessionState) (bool, error)
	// Close closes the auth connection if any.
	Close() error
}

// NewAuthorizeClient returns a new authorize service client.
func NewAuthorizeClient(name string, opts *Options) (a Authorizer, err error) {
	// Only gRPC is supported and is always returned so name is ignored
	return NewGRPCAuthorizeClient(opts)
}

// NewGRPCAuthorizeClient returns a new authorize service client.
func NewGRPCAuthorizeClient(opts *Options) (p *AuthorizeGRPC, err error) {
	conn, err := NewGRPCClientConn(opts)
	if err != nil {
		return nil, err
	}
	client := pb.NewAuthorizerClient(conn)
	return &AuthorizeGRPC{Conn: conn, client: client}, nil
}

// AuthorizeGRPC is a gRPC implementation of an authenticator (authenticate client)
type AuthorizeGRPC struct {
	Conn   *grpc.ClientConn
	client pb.AuthorizerClient
}

// Authorize makes an RPC call to the authorize service to creates a session state
// from an encrypted code provided as a result of an oauth2 callback process.
func (a *AuthorizeGRPC) Authorize(ctx context.Context, route string, s *sessions.SessionState) (bool, error) {
	if s == nil {
		return false, errors.New("session cannot be nil")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	response, err := a.client.Authorize(ctx, &pb.AuthorizeRequest{
		Route:  route,
		User:   s.User,
		Email:  s.Email,
		Groups: s.Groups,
	})
	return response.GetIsValid(), err
}

// Close tears down the ClientConn and all underlying connections.
func (a *AuthorizeGRPC) Close() error {
	return a.Conn.Close()
}
