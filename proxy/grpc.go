package proxy // import "github.com/pomerium/pomerium/proxy"
import (
	"context"
	"errors"
	"time"

	"github.com/golang/protobuf/ptypes"

	"github.com/pomerium/pomerium/internal/sessions"
	pb "github.com/pomerium/pomerium/proto/authenticate"
)

// AuthenticateRedeem makes an RPC call to the authenticate service to creates a session state
// from an encrypted code provided as a result of an oauth2 callback process.
func (p *Proxy) AuthenticateRedeem(code string) (*sessions.SessionState, error) {
	if code == "" {
		return nil, errors.New("missing code")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	r, err := p.AuthenticatorClient.Authenticate(ctx, &pb.AuthenticateRequest{Code: code})
	if err != nil {
		return nil, err
	}
	expiry, err := ptypes.Timestamp(r.Expiry)
	if err != nil {
		return nil, err
	}
	return &sessions.SessionState{
		AccessToken:      r.AccessToken,
		RefreshToken:     r.RefreshToken,
		IDToken:          r.IdToken,
		User:             r.User,
		Email:            r.Email,
		RefreshDeadline:  (expiry).Truncate(time.Second),
		LifetimeDeadline: extendDeadline(p.CookieLifetimeTTL),
		ValidDeadline:    extendDeadline(p.CookieExpire),
	}, nil
}

// AuthenticateRefresh makes an RPC call to the authenticate service to attempt to refresh the
// user's session. Requires a valid refresh token. Will return an error if the identity provider
// has revoked the session or if the refresh token is no longer valid in this context.
func (p *Proxy) AuthenticateRefresh(refreshToken string) (string, time.Time, error) {
	if refreshToken == "" {
		return "", time.Time{}, errors.New("missing refresh token")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	r, err := p.AuthenticatorClient.Refresh(ctx, &pb.RefreshRequest{RefreshToken: refreshToken})
	if err != nil {
		return "", time.Time{}, err
	}

	expiry, err := ptypes.Timestamp(r.Expiry)
	if err != nil {
		return "", time.Time{}, err
	}
	return r.AccessToken, expiry, nil
}

// AuthenticateValidate makes an RPC call to the authenticate service to validate the JWT id token;
// does NOT do nonce or revokation validation.
// https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
func (p *Proxy) AuthenticateValidate(idToken string) (bool, error) {
	if idToken == "" {
		return false, errors.New("missing id token")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	r, err := p.AuthenticatorClient.Validate(ctx, &pb.ValidateRequest{IdToken: idToken})
	if err != nil {
		return false, err
	}
	return r.IsValid, nil
}

func extendDeadline(ttl time.Duration) time.Time {
	return time.Now().Add(ttl).Truncate(time.Second)
}
