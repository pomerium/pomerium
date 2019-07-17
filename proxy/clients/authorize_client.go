package clients // import "github.com/pomerium/pomerium/proxy/clients"

import (
	"context"
	"errors"
	"time"

	"github.com/pomerium/pomerium/internal/telemetry"
	"google.golang.org/grpc"

	"github.com/pomerium/pomerium/internal/sessions"
	pb "github.com/pomerium/pomerium/proto/authorize"
)

// Authorizer provides the authorize service interface
type Authorizer interface {
	// Authorize takes a route and user session and returns whether the
	// request is valid per access policy
	Authorize(context.Context, string, *sessions.SessionState) (bool, error)
	// IsAdmin takes a session and returns whether the user is an administrator
	IsAdmin(context.Context, *sessions.SessionState) (bool, error)
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

// AuthorizeGRPC is a gRPC implementation of an authenticator (authorize client)
type AuthorizeGRPC struct {
	Conn   *grpc.ClientConn
	client pb.AuthorizerClient
}

// Authorize takes a route and user session and returns whether the
// request is valid per access policy
func (a *AuthorizeGRPC) Authorize(ctx context.Context, route string, s *sessions.SessionState) (bool, error) {
	ctx, span := telemetry.StartSpan(ctx, "proxy.client.grpc.Authorize")
	defer span.End()

	if s == nil {
		return false, errors.New("session cannot be nil")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	response, err := a.client.Authorize(ctx, &pb.Identity{
		Route:             route,
		User:              s.User,
		Email:             s.Email,
		Groups:            s.Groups,
		ImpersonateEmail:  s.ImpersonateEmail,
		ImpersonateGroups: s.ImpersonateGroups,
	})
	return response.GetIsValid(), err
}

// IsAdmin takes a session and returns whether the user is an administrator
func (a *AuthorizeGRPC) IsAdmin(ctx context.Context, s *sessions.SessionState) (bool, error) {
	ctx, span := telemetry.StartSpan(ctx, "proxy.client.grpc.Authorize")
	defer span.End()

	if s == nil {
		return false, errors.New("session cannot be nil")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	response, err := a.client.IsAdmin(ctx, &pb.Identity{Email: s.Email, Groups: s.Groups})
	return response.GetIsAdmin(), err
}

// Close tears down the ClientConn and all underlying connections.
func (a *AuthorizeGRPC) Close() error {
	return a.Conn.Close()
}
