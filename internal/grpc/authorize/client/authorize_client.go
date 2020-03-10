// Package client implements a gRPC client for the authorization service.
package client

import (
	"context"
	"net/http"

	"github.com/pomerium/pomerium/internal/grpc/authorize"
	pb "github.com/pomerium/pomerium/internal/grpc/authorize"
	"github.com/pomerium/pomerium/internal/telemetry/trace"

	"google.golang.org/grpc"
)

// Authorizer provides the authorize service interface
type Authorizer interface {
	// Authorize takes a route and user session and returns whether the
	// request is valid per access policy
	Authorize(ctx context.Context, user string, r *http.Request) (*pb.IsAuthorizedReply, error)
	// Close closes the auth connection if any.
	Close() error
}

// Client is a gRPC implementation of an authenticator (authorize client)
type Client struct {
	conn   *grpc.ClientConn
	client pb.AuthorizerClient
}

// New returns a new authorize service client.
func New(conn *grpc.ClientConn) (p *Client, err error) {
	return &Client{conn: conn, client: pb.NewAuthorizerClient(conn)}, nil
}

// Authorize takes a route and user session and returns whether the
// request is valid per access policy
func (c *Client) Authorize(ctx context.Context, user string, r *http.Request) (*pb.IsAuthorizedReply, error) {
	ctx, span := trace.StartSpan(ctx, "grpc.authorize.client.Authorize")
	defer span.End()
	in := &pb.IsAuthorizedRequest{
		UserToken:         user,
		RequestHost:       r.Host,
		RequestMethod:     r.Method,
		RequestHeaders:    cloneHeaders(r.Header),
		RequestRemoteAddr: r.RemoteAddr,
		RequestRequestUri: r.RequestURI,
		RequestUrl:        r.URL.String(),
	}
	return c.client.IsAuthorized(ctx, in)
}

// Close tears down the ClientConn and all underlying connections.
func (c *Client) Close() error {
	return c.conn.Close()
}

type protoHeader map[string]*authorize.IsAuthorizedRequest_Headers

func cloneHeaders(in http.Header) protoHeader {
	out := make(protoHeader, len(in))
	for key, values := range in {
		newValues := make([]string, len(values))
		copy(newValues, values)
		out[key] = &authorize.IsAuthorizedRequest_Headers{Value: newValues}
	}
	return out
}
