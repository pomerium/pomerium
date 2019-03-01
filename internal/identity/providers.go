//go:generate protoc -I ../../proto/authenticate --go_out=plugins=grpc:../../proto/authenticate ../../proto/authenticate/authenticate.proto

// Package identity provides support for making OpenID Connect and OAuth2 authorized and
// authenticated HTTP requests with third party identity providers.
package identity // import "github.com/pomerium/pomerium/internal/identity"

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

// ErrMissingProviderURL is returned when an identity provider requires a provider url
// does not receive one.
var ErrMissingProviderURL = errors.New("identity: missing provider url")

// UserGrouper is an interface representing the ability to retrieve group membership information
// from an identity provider
type UserGrouper interface {
	// UserGroups returns a slice of group names a given user is in
	UserGroups(context.Context, string) ([]string, error)
}

// Authenticator is an interface representing the ability to authenticate with an identity provider.
type Authenticator interface {
	Authenticate(string) (*sessions.SessionState, error)
	Validate(context.Context, string) (bool, error)
	Refresh(context.Context, *sessions.SessionState) (*sessions.SessionState, error)
	Revoke(string) error
	GetSignInURL(state string) string
}

// New returns a new identity provider based given its name.
// Returns an error if selected provided not found or if the identity provider is not known.
func New(providerName string, p *Provider) (a Authenticator, err error) {
	switch providerName {
	case AzureProviderName:
		a, err = NewAzureProvider(p)
	case GitlabProviderName:
		return nil, fmt.Errorf("identity: %s currently not supported", providerName)
	case GoogleProviderName:
		a, err = NewGoogleProvider(p)
	case OIDCProviderName:
		a, err = NewOIDCProvider(p)
	case OktaProviderName:
		a, err = NewOktaProvider(p)
	case OneLoginProviderName:
		a, err = NewOneLoginProvider(p)
	default:
		return nil, fmt.Errorf("identity: %s provider not known", providerName)
	}
	if err != nil {
		return nil, err
	}
	return a, nil
}

// Provider contains the fields required for an OAuth 2.0 Authorization Request that
// requests that the End-User be authenticated by the Authorization Server.
// https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
type Provider struct {
	ProviderName string

	RedirectURL        *url.URL
	ClientID           string
	ClientSecret       string
	ProviderURL        string
	Scopes             []string
	SessionLifetimeTTL time.Duration

	// Some providers, such as google, require additional remote api calls to retrieve
	// user details like groups. Provider is responsible for parsing.
	ServiceAccount string

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
func (p *Provider) GetSignInURL(state string) string {
	return p.oauth.AuthCodeURL(state, oauth2.AccessTypeOffline)
}

// Validate validates a given session's from it's JWT token
// The function verifies it's been signed by the provider, preforms
// any additional checks depending on the Config, and returns the payload.
//
// Validate does NOT do nonce validation.
// Validate does NOT check if revoked.
// https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
func (p *Provider) Validate(ctx context.Context, idToken string) (bool, error) {
	_, err := p.verifier.Verify(ctx, idToken)
	if err != nil {
		log.Error().Err(err).Msg("identity: failed to verify session state")
		return false, err
	}
	return true, nil
}

// Authenticate creates a session with an identity provider from a authorization code
func (p *Provider) Authenticate(code string) (*sessions.SessionState, error) {
	ctx := context.Background()
	// convert authorization code into a token
	oauth2Token, err := p.oauth.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("identity: failed token exchange: %v", err)
	}
	//id_token contains claims about the authenticated user
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("token response did not contain an id_token")
	}
	// Parse and verify ID Token payload.
	idToken, err := p.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("identity: could not verify id_token: %v", err)
	}

	// Extract id_token which contains claims about the authenticated user
	var claims struct {
		Email         string   `json:"email"`
		EmailVerified bool     `json:"email_verified"`
		Groups        []string `json:"groups"`
	}
	// parse claims from the raw, encoded jwt token
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("identity: failed to parse id_token claims: %v", err)
	}

	return &sessions.SessionState{
		IDToken:          rawIDToken,
		AccessToken:      oauth2Token.AccessToken,
		RefreshToken:     oauth2Token.RefreshToken,
		RefreshDeadline:  oauth2Token.Expiry.Truncate(time.Second),
		LifetimeDeadline: sessions.ExtendDeadline(p.SessionLifetimeTTL),
		Email:            claims.Email,
		User:             idToken.Subject,
		Groups:           claims.Groups,
	}, nil
}

// Refresh renews a user's session using an oid refresh token without reprompting the user.
// Group membership is also refreshed.
// https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokens
func (p *Provider) Refresh(ctx context.Context, s *sessions.SessionState) (*sessions.SessionState, error) {
	if s.RefreshToken == "" {
		return nil, errors.New("identity: missing refresh token")
	}
	t := oauth2.Token{RefreshToken: s.RefreshToken}
	newToken, err := p.oauth.TokenSource(ctx, &t).Token()
	if err != nil {
		log.Error().Err(err).Msg("identity: refresh failed")
		return nil, err
	}
	s.AccessToken = newToken.AccessToken
	s.RefreshDeadline = newToken.Expiry.Truncate(time.Second)
	return s, nil
}

// Revoke enables a user to revoke her token. If the identity provider supports revocation
// the endpoint is available, otherwise an error is thrown.
func (p *Provider) Revoke(token string) error {
	return fmt.Errorf("identity: revoke not implemented by %s", p.ProviderName)
}
