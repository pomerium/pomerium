//go:generate protoc -I ../proto/authenticate --go_out=plugins=grpc:../proto/authenticate ../proto/authenticate/authenticate.proto

package authenticate // import "github.com/pomerium/pomerium/authenticate"
import (
	"context"
	"fmt"

	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/telemetry"
	pb "github.com/pomerium/pomerium/proto/authenticate"
)

// Authenticate takes an encrypted code, and returns the authentication result.
func (p *Authenticate) Authenticate(ctx context.Context, in *pb.AuthenticateRequest) (*pb.Session, error) {
	_, span := telemetry.StartSpan(ctx, "authenticate.grpc.Authenticate")
	defer span.End()
	session, err := sessions.UnmarshalSession(in.Code, p.cipher)
	if err != nil {
		return nil, fmt.Errorf("authenticate/grpc: authenticate %v", err)
	}
	newSessionProto, err := pb.ProtoFromSession(session)
	if err != nil {
		return nil, err
	}
	return newSessionProto, nil
}

// Validate locally validates a JWT id_token; does NOT do nonce or revokation validation.
// https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
func (p *Authenticate) Validate(ctx context.Context, in *pb.ValidateRequest) (*pb.ValidateReply, error) {
	ctx, span := telemetry.StartSpan(ctx, "authenticate.grpc.Validate")
	defer span.End()

	isValid, err := p.provider.Validate(ctx, in.IdToken)
	if err != nil {
		return &pb.ValidateReply{IsValid: false}, fmt.Errorf("authenticate/grpc: validate %v", err)
	}
	return &pb.ValidateReply{IsValid: isValid}, nil
}

// Refresh renews a user's session checks if the session has been revoked using an access token
// without reprompting the user.
func (p *Authenticate) Refresh(ctx context.Context, in *pb.Session) (*pb.Session, error) {
	ctx, span := telemetry.StartSpan(ctx, "authenticate.grpc.Refresh")
	defer span.End()
	if in == nil {
		return nil, fmt.Errorf("authenticate/grpc: session cannot be nil")
	}
	oldSession, err := pb.SessionFromProto(in)
	if err != nil {
		return nil, err
	}
	newSession, err := p.provider.Refresh(ctx, oldSession)
	if err != nil {
		return nil, fmt.Errorf("authenticate/grpc: refresh failed %v", err)
	}
	newSessionProto, err := pb.ProtoFromSession(newSession)
	if err != nil {
		return nil, err
	}
	return newSessionProto, nil
}
