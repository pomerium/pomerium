package authenticator // import "github.com/pomerium/pomerium/proxy/authenticator"
import (
	"context"
	"errors"
	"time"

	"github.com/golang/protobuf/ptypes"
	"google.golang.org/grpc"

	pb "github.com/pomerium/pomerium/proto/authenticate"
)

// RedeemResponse contains data from a authenticator redeem request.
type RedeemResponse struct {
	AccessToken  string
	RefreshToken string
	IDToken      string
	User         string
	Email        string
	Expiry       time.Time
}

// AuthenticateGRPC is a gRPC implementation of an authenticator (authenticate client)
type AuthenticateGRPC struct {
	conn   *grpc.ClientConn
	client pb.AuthenticatorClient
}

// Redeem makes an RPC call to the authenticate service to creates a session state
// from an encrypted code provided as a result of an oauth2 callback process.
func (a *AuthenticateGRPC) Redeem(code string) (*RedeemResponse, error) {
	if code == "" {
		return nil, errors.New("missing code")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	r, err := a.client.Authenticate(ctx, &pb.AuthenticateRequest{Code: code})
	if err != nil {
		return nil, err
	}
	expiry, err := ptypes.Timestamp(r.Expiry)
	if err != nil {
		return nil, err
	}
	return &RedeemResponse{
		AccessToken:  r.AccessToken,
		RefreshToken: r.RefreshToken,
		IDToken:      r.IdToken,
		User:         r.User,
		Email:        r.Email,
		Expiry:       expiry,
		// RefreshDeadline:  (expiry).Truncate(time.Second),
		// LifetimeDeadline: extendDeadline(p.CookieLifetimeTTL),
		// ValidDeadline:    extendDeadline(p.CookieExpire),
	}, nil
}

// Refresh makes an RPC call to the authenticate service to attempt to refresh the
// user's session. Requires a valid refresh token. Will return an error if the identity provider
// has revoked the session or if the refresh token is no longer valid in this context.
func (a *AuthenticateGRPC) Refresh(refreshToken string) (string, time.Time, error) {
	if refreshToken == "" {
		return "", time.Time{}, errors.New("missing refresh token")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	r, err := a.client.Refresh(ctx, &pb.RefreshRequest{RefreshToken: refreshToken})
	if err != nil {
		return "", time.Time{}, err
	}

	expiry, err := ptypes.Timestamp(r.Expiry)
	if err != nil {
		return "", time.Time{}, err
	}
	return r.AccessToken, expiry, nil
}

// Validate makes an RPC call to the authenticate service to validate the JWT id token;
// does NOT do nonce or revokation validation.
// https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
func (a *AuthenticateGRPC) Validate(idToken string) (bool, error) {
	if idToken == "" {
		return false, errors.New("missing id token")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	r, err := a.client.Validate(ctx, &pb.ValidateRequest{IdToken: idToken})
	if err != nil {
		return false, err
	}
	return r.IsValid, nil
}

// Close tears down the ClientConn and all underlying connections.
func (a *AuthenticateGRPC) Close() error {
	return a.conn.Close()
}
