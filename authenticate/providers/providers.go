//go:generate protoc -I ../../proto/authenticate --go_out=plugins=grpc:../../proto/authenticate ../../proto/authenticate/authenticate.proto

package providers // import "github.com/pomerium/pomerium/internal/providers"

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"time"

	oidc "github.com/pomerium/go-oidc"
	"golang.org/x/oauth2"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/sessions"
)

const (
	// AzureProviderName identifies the Azure identity provider
	AzureProviderName = "azure"
	// GitlabProviderName identifies the GitLab identity provider
	GitlabProviderName = "gitlab"
	// GoogleProviderName identifies the Google identity provider
	GoogleProviderName = "google"
	// OIDCProviderName identifies a generic OpenID connect provider
	OIDCProviderName = "oidc"
	// OktaProviderName identifies the Okta identity provider
	OktaProviderName = "okta"
	// OneLoginProviderName identifies the OneLogin identity provider
	OneLoginProviderName = "onelogin"
)

var (
	// ErrMissingProviderURL is returned when the CB state is half open and the requests count is over the cb maxRequests
	ErrMissingProviderURL = errors.New("proxy/providers: missing provider url")
)

// Provider is an interface exposing functions necessary to interact with a given provider.
type Provider interface {
	Authenticate(string) (*sessions.SessionState, error)
	Validate(string) (bool, error)
	Refresh(string) (*oauth2.Token, error)
	Revoke(string) error
	GetSignInURL(state string) string
}

// New returns a new identity provider based given its name.
// Returns an error if selected provided not found or if the identity provider is not known.
func New(providerName string, pd *IdentityProvider) (p Provider, err error) {
	switch providerName {
	case AzureProviderName:
		p, err = NewAzureProvider(pd)
	case GitlabProviderName:
		p, err = NewGitlabProvider(pd)
	case GoogleProviderName:
		p, err = NewGoogleProvider(pd)
	case OIDCProviderName:
		p, err = NewOIDCProvider(pd)
	case OktaProviderName:
		p, err = NewOktaProvider(pd)
	case OneLoginProviderName:
		p, err = NewOneLoginProvider(pd)
	default:
		return nil, fmt.Errorf("authenticate: %q name not found", providerName)
	}
	if err != nil {
		return nil, err
	}
	return p, nil
}

// IdentityProvider contains the fields required for an OAuth 2.0 Authorization Request that
// requests that the End-User be authenticated by the Authorization Server.
// https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
type IdentityProvider struct {
	ProviderName string

	RedirectURL        *url.URL
	ClientID           string
	ClientSecret       string
	ProviderURL        string
	Scopes             []string
	SessionLifetimeTTL time.Duration

	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
	oauth    *oauth2.Config
}

// GetSignInURL returns a URL to OAuth 2.0 provider's consent page
// that asks for permissions for the required scopes explicitly.
//
// State is a token to protect the user from CSRF attacks. You must
// always provide a non-empty string and validate that it matches the
// the state query parameter on your redirect callback.
// See http://tools.ietf.org/html/rfc6749#section-10.12 for more info.
func (p *IdentityProvider) GetSignInURL(state string) string {
	return p.oauth.AuthCodeURL(state)
}

// Validate validates a given session's from it's JWT token
// The function verifies it's been signed by the provider, preforms
// any additional checks depending on the Config, and returns the payload.
//
// Validate does NOT do nonce validation.
// Validate does NOT check if revoked.
// https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
func (p *IdentityProvider) Validate(idToken string) (bool, error) {
	ctx := context.Background()
	_, err := p.verifier.Verify(ctx, idToken)
	if err != nil {
		log.Error().Err(err).Msg("authenticate/providers: failed to verify session state")
		return false, err
	}
	return true, nil
}

// Authenticate creates a session with an identity provider from a authorization code
func (p *IdentityProvider) Authenticate(code string) (*sessions.SessionState, error) {
	ctx := context.Background()
	// convert authorization code into a token
	oauth2Token, err := p.oauth.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("authenticate/providers: failed token exchange: %v", err)
	}
	log.Info().
		Str("RefreshToken", oauth2Token.RefreshToken).
		Str("TokenType", oauth2Token.TokenType).
		Str("AccessToken", oauth2Token.AccessToken).
		Msg("Authenticate - oauth.Exchange")

		//id_token contains claims about the authenticated user
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("token response did not contain an id_token")
	}

	// Parse and verify ID Token payload.
	idToken, err := p.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("authenticate/providers: could not verify id_token: %v", err)
	}

	// Extract id_token which contains claims about the authenticated user
	var claims struct {
		Email         string   `json:"email"`
		EmailVerified bool     `json:"email_verified"`
		Groups        []string `json:"groups"`
	}
	// parse claims from the raw, encoded jwt token
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("authenticate/providers: failed to parse id_token claims: %v", err)
	}

	return &sessions.SessionState{
		IDToken:          rawIDToken,
		AccessToken:      oauth2Token.AccessToken,
		RefreshToken:     oauth2Token.RefreshToken,
		RefreshDeadline:  oauth2Token.Expiry,
		LifetimeDeadline: sessions.ExtendDeadline(p.SessionLifetimeTTL),
		Email:            claims.Email,
		User:             idToken.Subject,
		Groups:           claims.Groups,
	}, nil
}

// Refresh renews a user's session using an access token without reprompting the user.
func (p *IdentityProvider) Refresh(refreshToken string) (*oauth2.Token, error) {
	if refreshToken == "" {
		return nil, errors.New("authenticate/providers: missing refresh token")
	}
	t := oauth2.Token{RefreshToken: refreshToken}
	newToken, err := p.oauth.TokenSource(context.Background(), &t).Token()
	if err != nil {
		log.Error().Err(err).Msg("authenticate/providers.Refresh")
		return nil, err
	}
	log.Info().
		Str("RefreshToken", refreshToken).
		Str("newToken.AccessToken", newToken.AccessToken).
		Str("time.Until(newToken.Expiry)", time.Until(newToken.Expiry).String()).
		Msg("authenticate/providers.Refresh")

	return newToken, nil
}

// Revoke enables a user to revoke her token. If the identity provider supports revocation
// the endpoint is available, otherwise an error is thrown.
func (p *IdentityProvider) Revoke(token string) error {
	return errors.New("authenticate/providers: revoke not implemented")
}
