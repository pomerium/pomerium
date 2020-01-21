package client

import (
	"context"
	"errors"

	pb "github.com/pomerium/pomerium/internal/grpc/authorize"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/telemetry/trace"

	"google.golang.org/grpc"
)

// Authorizer provides the authorize service interface
type Authorizer interface {
	// Authorize takes a route and user session and returns whether the
	// request is valid per access policy
	Authorize(context.Context, string, *sessions.State) (bool, error)
	// IsAdmin takes a session and returns whether the user is an administrator
	IsAdmin(context.Context, *sessions.State) (bool, error)
	// Close closes the auth connection if any.
	Close() error
}

// Client is a gRPC implementation of an authenticator (authorize client)
type Client struct {
	Conn   *grpc.ClientConn
	client pb.AuthorizerClient
}

// New returns a new authorize service client.
func New(conn *grpc.ClientConn) (p *Client, err error) {
	return &Client{Conn: conn, client: pb.NewAuthorizerClient(conn)}, nil
}

// Authorize takes a route and user session and returns whether the
// request is valid per access policy
func (c *Client) Authorize(ctx context.Context, route string, s *sessions.State) (bool, error) {
	ctx, span := trace.StartSpan(ctx, "grpc.authorize.client.Authorize")
	defer span.End()

	if s == nil {
		return false, errors.New("session cannot be nil")
	}
	response, err := c.client.Authorize(ctx, &pb.Identity{
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
func (c *Client) IsAdmin(ctx context.Context, s *sessions.State) (bool, error) {
	ctx, span := trace.StartSpan(ctx, "grpc.authorize.client.IsAdmin")
	defer span.End()

	if s == nil {
		return false, errors.New("session cannot be nil")
	}
	response, err := c.client.IsAdmin(ctx, &pb.Identity{Email: s.Email, Groups: s.Groups})
	return response.GetIsAdmin(), err
}

// Close tears down the ClientConn and all underlying connections.
func (c *Client) Close() error {
	return c.Conn.Close()
}
