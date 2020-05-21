// Package evaluator defines a Evaluator interfaces that can be implemented by
// a policy evaluator framework.
package evaluator

import (
	"context"

	pb "github.com/pomerium/pomerium/internal/grpc/authorize"
)

// Evaluator specifies the interface for a policy engine.
type Evaluator interface {
	IsAuthorized(ctx context.Context, req *Request) (*pb.IsAuthorizedReply, error)
	PutData(ctx context.Context, data map[string]interface{}) error
}

// A Request represents an evaluable request with an associated user, device,
// and request context.
type Request struct {
	// User context
	//
	// User contains the associated user's JWT created by the authenticate
	// service
	User string `json:"user,omitempty"`

	// Request context
	//
	// Method specifies the HTTP method (GET, POST, PUT, etc.).
	Method string `json:"method,omitempty"`
	// URL specifies either the URI being requested.
	URL string `json:"url,omitempty"`
	// The protocol version for incoming server requests.
	Proto string `json:"proto,omitempty"` // "HTTP/1.0"
	// Header contains the request header fields either received
	// by the server or to be sent by the client.
	Header map[string][]string `json:"headers,omitempty"`
	// Host specifies the host on which the URL is sought.
	Host string `json:"host,omitempty"`
	// RemoteAddr is the network address that sent the request.
	RemoteAddr string `json:"remote_addr,omitempty"`
	// RequestURI is the unmodified request-target of the
	// Request-Line (RFC 7230, Section 3.1.1) as sent by the client
	// to a server. Usually the URL field should be used instead.
	// It is an error to set this field in an HTTP client request.
	RequestURI string `json:"request_uri,omitempty"`

	// Connection context
	//
	// ClientCertificate is the PEM-encoded public certificate used for the user's TLS connection.
	ClientCertificate string `json:"client_certificate"`

	// Device context
	//
	// todo(bdd):  Use the peer TLS certificate to bind device state with a request
}
