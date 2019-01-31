package authenticate // import "github.com/pomerium/pomerium/authenticate"
import (
	"context"
	"fmt"

	"github.com/golang/protobuf/ptypes"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/sessions"
	pb "github.com/pomerium/pomerium/proto/authenticate"
)

// Authenticate takes an encrypted code, and returns the authentication result.
func (p *Authenticate) Authenticate(ctx context.Context, in *pb.AuthenticateRequest) (*pb.AuthenticateReply, error) {
	session, err := sessions.UnmarshalSession(in.Code, p.cipher)
	if err != nil {
		return nil, fmt.Errorf("authenticate/grpc: %v", err)
	}
	expiryTimestamp, err := ptypes.TimestampProto(session.RefreshDeadline)
	if err != nil {
		return nil, err
	}

	return &pb.AuthenticateReply{
		AccessToken:  session.AccessToken,
		RefreshToken: session.RefreshToken,
		IdToken:      session.IDToken,
		User:         session.User,
		Email:        session.Email,
		Expiry:       expiryTimestamp,
	}, nil
}

// Validate locally validates a JWT id token; does NOT do nonce or revokation validation.
// https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
func (p *Authenticate) Validate(ctx context.Context, in *pb.ValidateRequest) (*pb.ValidateReply, error) {
	isValid, err := p.provider.Validate(in.IdToken)
	if err != nil {
		return &pb.ValidateReply{IsValid: false}, err
	}
	return &pb.ValidateReply{IsValid: isValid}, nil
}

// Refresh renews a user's session checks if the session has been revoked using an access token
// without reprompting the user.
func (p *Authenticate) Refresh(ctx context.Context, in *pb.RefreshRequest) (*pb.RefreshReply, error) {
	newToken, err := p.provider.Refresh(in.RefreshToken)
	if err != nil {
		return nil, err
	}
	expiryTimestamp, err := ptypes.TimestampProto(newToken.Expiry)
	if err != nil {
		return nil, err
	}
	log.Info().
		Str("session.AccessToken", newToken.AccessToken).
		Msg("authenticate: grpc: refresh: ok")

	return &pb.RefreshReply{
		AccessToken: newToken.AccessToken,
		Expiry:      expiryTimestamp,
	}, nil

}
