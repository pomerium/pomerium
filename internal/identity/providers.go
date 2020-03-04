// Package identity provides support for making OpenID Connect (OIDC)
// and OAuth2 authenticated HTTP requests with third party identity providers.
package identity // import "github.com/pomerium/pomerium/internal/identity"

import (
	"context"
	"errors"
	"fmt"
	"net/url"

	"github.com/pomerium/pomerium/internal/sessions"

	oidc "github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
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
var ErrMissingProviderURL = errors.New("internal/identity: missing provider url")

// Authenticator is an interface representing the ability to authenticate with an identity provider.
type Authenticator interface {
	Authenticate(context.Context, string) (*sessions.State, error)
	Refresh(context.Context, *sessions.State) (*sessions.State, error)
	Revoke(context.Context, *oauth2.Token) error
	GetSignInURL(state string) string
}

// New returns a new identity provider based on its name.
// Returns an error if selected provided not found or if the identity provider is not known.
func New(providerName string, p *Provider) (a Authenticator, err error) {
	switch providerName {
	case AzureProviderName:
		a, err = NewAzureProvider(p)
	case GitlabProviderName:
		a, err = NewGitLabProvider(p)
	case GoogleProviderName:
		a, err = NewGoogleProvider(p)
	case OIDCProviderName:
		a, err = NewOIDCProvider(p)
	case OktaProviderName:
		a, err = NewOktaProvider(p)
	case OneLoginProviderName:
		a, err = NewOneLoginProvider(p)
	default:
		return nil, fmt.Errorf("internal/identity: %s provider not known", providerName)
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

	RedirectURL *url.URL

	ClientID     string
	ClientSecret string
	ProviderURL  string
	Scopes       []string

	UserGroupFn func(context.Context, *sessions.State) ([]string, error)

	UserInfoEndpoint bool

	// ServiceAccount can be set for those providers that require additional
	// credentials or tokens to do follow up API calls (e.g. Google)
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

// Authenticate creates an identity session with google from a authorization code, and follows up
// call to the admin/group api to check what groups the user is in.
func (p *Provider) Authenticate(ctx context.Context, code string) (*sessions.State, error) {
	oauth2Token, err := p.oauth.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("internal/identity: token exchange failed: %w", err)
	}
	idToken, err := p.IdentityFromToken(ctx, oauth2Token)
	if err != nil {
		return nil, err
	}

	s, err := sessions.NewStateFromTokens(idToken, oauth2Token, p.RedirectURL.Hostname())
	if err != nil {
		return nil, err
	}

	// check if provider has info endpoint, try to hit that and gather more info
	// especially useful if initial request did not an contain email, or subject
	// https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
	var claims struct {
		UserInfoURL string `json:"userinfo_endpoint"`
	}

	if err := p.provider.Claims(&claims); err == nil && claims.UserInfoURL != "" {
		userInfo, err := p.provider.UserInfo(ctx, oauth2.StaticTokenSource(oauth2Token))
		if err != nil {
			return nil, fmt.Errorf("internal/identity: could not retrieve user info %w", err)
		}
		if err := userInfo.Claims(&s); err != nil {
			return nil, err
		}
	}

	if p.UserGroupFn != nil {
		s.Groups, err = p.UserGroupFn(ctx, s)
		if err != nil {
			return nil, fmt.Errorf("internal/identity: could not retrieve groups %w", err)
		}
	}
	return s, nil
}

// Refresh renews a user's session using an oidc refresh token withoutreprompting the user.
// Group membership is also refreshed.
// https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokens
func (p *Provider) Refresh(ctx context.Context, s *sessions.State) (*sessions.State, error) {
	if s.AccessToken == nil || s.AccessToken.RefreshToken == "" {
		return nil, errors.New("internal/identity: missing refresh token")
	}

	t := oauth2.Token{RefreshToken: s.AccessToken.RefreshToken}
	oauthToken, err := p.oauth.TokenSource(ctx, &t).Token()
	if err != nil {
		return nil, fmt.Errorf("internal/identity: refresh failed %w", err)
	}
	idToken, err := p.IdentityFromToken(ctx, oauthToken)
	if err != nil {
		return nil, err
	}
	if err := s.UpdateState(idToken, oauthToken); err != nil {
		return nil, fmt.Errorf("internal/identity: state update failed %w", err)
	}
	if p.UserGroupFn != nil {
		s.Groups, err = p.UserGroupFn(ctx, s)
		if err != nil {
			return nil, fmt.Errorf("internal/identity: could not retrieve groups %w", err)
		}
	}
	return s, nil
}

// IdentityFromToken takes an identity provider issued JWT as input ('id_token')
// and returns a session state. The provided token's audience ('aud') must
// match Pomerium's client_id.
func (p *Provider) IdentityFromToken(ctx context.Context, t *oauth2.Token) (*oidc.IDToken, error) {
	rawIDToken, ok := t.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("internal/identity: id_token not found")
	}
	return p.verifier.Verify(ctx, rawIDToken)
}

// Revoke enables a user to revoke her token. If the identity provider supports revocation
// the endpoint is available, otherwise an error is thrown.
func (p *Provider) Revoke(ctx context.Context, token *oauth2.Token) error {
	return fmt.Errorf("internal/identity: revoke not implemented by %s", p.ProviderName)
}
