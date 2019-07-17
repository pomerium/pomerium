package clients // import "github.com/pomerium/pomerium/proxy/clients"

import (
	"context"
	"errors"
	"time"

	"github.com/pomerium/pomerium/internal/telemetry"
	"google.golang.org/grpc"

	"github.com/pomerium/pomerium/internal/sessions"
	pb "github.com/pomerium/pomerium/proto/authenticate"
)

// Authenticator provides the authenticate service interface
type Authenticator interface {
	// Redeem takes a code and returns a validated session or an error
	Redeem(context.Context, string) (*sessions.SessionState, error)
	// Refresh attempts to refresh a valid session with a refresh token. Returns a refreshed session.
	Refresh(context.Context, *sessions.SessionState) (*sessions.SessionState, error)
	// Validate evaluates a given oidc id_token for validity. Returns validity and any error.
	Validate(context.Context, string) (bool, error)
	// Close closes the authenticator connection if any.
	Close() error
}

// NewAuthenticateClient returns a new authenticate service client. Presently,
// only gRPC is supported and is always returned so name is ignored.
func NewAuthenticateClient(name string, opts *Options) (a Authenticator, err error) {
	return NewGRPCAuthenticateClient(opts)
}

// NewGRPCAuthenticateClient returns a new authenticate service client.
func NewGRPCAuthenticateClient(opts *Options) (p *AuthenticateGRPC, err error) {
	conn, err := NewGRPCClientConn(opts)
	if err != nil {
		return nil, err
	}
	authClient := pb.NewAuthenticatorClient(conn)
	return &AuthenticateGRPC{Conn: conn, client: authClient}, nil
}

// AuthenticateGRPC is a gRPC implementation of an authenticator (authenticate client)
type AuthenticateGRPC struct {
	Conn   *grpc.ClientConn
	client pb.AuthenticatorClient
}

// Redeem makes an RPC call to the authenticate service to creates a session state
// from an encrypted code provided as a result of an oauth2 callback process.
func (a *AuthenticateGRPC) Redeem(ctx context.Context, code string) (*sessions.SessionState, error) {
	ctx, span := telemetry.StartSpan(ctx, "proxy.client.grpc.Redeem")
	defer span.End()

	if code == "" {
		return nil, errors.New("missing code")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	protoSession, err := a.client.Authenticate(ctx, &pb.AuthenticateRequest{Code: code})
	if err != nil {
		return nil, err
	}
	session, err := pb.SessionFromProto(protoSession)
	if err != nil {
		return nil, err
	}
	return session, nil
}

// Refresh makes an RPC call to the authenticate service to attempt to refresh the
// user's session. Requires a valid refresh token. Will return an error if the identity provider
// has revoked the session or if the refresh token is no longer valid in this context.
func (a *AuthenticateGRPC) Refresh(ctx context.Context, s *sessions.SessionState) (*sessions.SessionState, error) {
	ctx, span := telemetry.StartSpan(ctx, "proxy.client.grpc.Refresh")
	defer span.End()

	if s.RefreshToken == "" {
		return nil, errors.New("missing refresh token")
	}
	req, err := pb.ProtoFromSession(s)
	if err != nil {
		return nil, err
	}
	// todo(bdd): handle request id in grpc receiver and add to ctx logger
	// reqID, ok := middleware.IDFromCtx(ctx)
	// if ok {
	// 	md := metadata.Pairs("req_id", reqID)
	// 	ctx = metadata.NewOutgoingContext(ctx, md)
	// }
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	// todo(bdd): add grpc specific timeouts to main options
	// todo(bdd): handle request id (metadata!?) in grpc receiver and add to ctx logger
	reply, err := a.client.Refresh(ctx, req)
	if err != nil {
		return nil, err
	}
	newSession, err := pb.SessionFromProto(reply)
	if err != nil {
		return nil, err
	}
	return newSession, nil
}

// Validate makes an RPC call to the authenticate service to validate the JWT id token;
// does NOT do nonce or revokation validation.
// https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
func (a *AuthenticateGRPC) Validate(ctx context.Context, idToken string) (bool, error) {
	ctx, span := telemetry.StartSpan(ctx, "proxy.client.grpc.Validate")
	defer span.End()

	if idToken == "" {
		return false, errors.New("missing id token")
	}
	// todo(bdd): add grpc specific timeouts to main options
	// todo(bdd): handle request id in grpc receiver and add to ctx logger
	// reqID, ok := middleware.IDFromCtx(ctx)
	// if ok {
	// 	md := metadata.Pairs("req_id", reqID)
	// 	ctx = metadata.NewOutgoingContext(ctx, md)
	// }
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	r, err := a.client.Validate(ctx, &pb.ValidateRequest{IdToken: idToken})
	if err != nil {
		return false, err
	}
	return r.IsValid, nil
}

// Close tears down the ClientConn and all underlying connections.
func (a *AuthenticateGRPC) Close() error {
	return a.Conn.Close()
}
