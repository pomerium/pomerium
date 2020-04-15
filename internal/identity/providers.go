// Package identity provides support for making OpenID Connect (OIDC)
// and OAuth2 authenticated HTTP requests with third party identity providers.
package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/version"

	oidc "github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

const (
	// AzureProviderName identifies the Azure identity provider
	AzureProviderName = "azure"
	// GitlabProviderName identifies the GitLab identity provider
	GitlabProviderName = "gitlab"
	// GithubProviderName identifies the GitHub identity provider
	GithubProviderName = "github"
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
	case GithubProviderName:
		a, err = NewGitHubProvider(p)
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

	// We will attempt to get the identity provider's possible information from
	// their /.well-known/openid-configuration.
	// https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
	UserInfoURL string `json:"userinfo_endpoint"`

	// RevocationURL is the location of the OAuth 2.0 token revocation endpoint.
	// https://tools.ietf.org/html/rfc7009
	RevocationURL string //can be empty
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

	s, err := sessions.NewStateFromTokens(idToken, oauth2Token, p.RedirectURL.Host)
	if err != nil {
		return nil, err
	}

	if err := p.provider.Claims(&p); err == nil && p.UserInfoURL != "" {
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

// Refresh renews a user's session using an oidc refresh token without reprompting the user.
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

// Revoke enables a user to revoke her token. If the identity provider does not
// support revocation an error is thrown.
//
// https://tools.ietf.org/html/rfc7009
func (p *Provider) Revoke(ctx context.Context, token *oauth2.Token) error {
	if p.RevocationURL == "" {
		return ErrRevokeNotImplemented
	}
	params := url.Values{}
	// https://tools.ietf.org/html/rfc7009#section-2.1
	params.Add("token", token.AccessToken)
	params.Add("token_type_hint", "access_token")
	// Some providers like okta / onelogin require "client authentication"
	// https://developer.okta.com/docs/reference/api/oidc/#client-secret
	// https://developers.onelogin.com/openid-connect/api/revoke-session
	params.Add("client_id", p.ClientID)
	params.Add("client_secret", p.ClientSecret)

	err := httputil.Client(ctx, http.MethodPost, p.RevocationURL, version.UserAgent(), nil, params, nil)
	if err != nil && err != httputil.ErrTokenRevoked {
		return err
	}

	return nil
}

// UnmarshalJSON method is needed so that provider will be able to
// satisfy the Unmarshaler interface
// https://pkg.go.dev/gopkg.in/square/go-jose.v2/json#Unmarshaler
//
// For the the go-oidc package to be able to apply the Claims method which tries to unmarshal
// the response body from the provider's /.well-known/openid-configuration
// on the supplied interface, and in our case, it will be the Provider.
// An extra step is made to create this implementation because the endpoint
// to revoke a user's access token can be revocation_endpoint or end_session_endpoint.
// We want to be able to have only one field and not repeat any of the two possible
// endpoints on the Provider field.
func (p *Provider) UnmarshalJSON(b []byte) error {
	type Alias Provider
	t := &struct {
		*Alias
		EndSessionEndpoint string `json:"end_session_endpoint,omitempty"`
		RevocationEndpoint string `json:"revocation_endpoint,omitempty"`
	}{
		Alias: (*Alias)(p),
	}
	if err := json.Unmarshal(b, &t); err != nil {
		return err
	}
	if t.EndSessionEndpoint != "" {
		t.RevocationURL = t.EndSessionEndpoint
	}
	if t.RevocationEndpoint != "" {
		t.RevocationURL = t.RevocationEndpoint
	}
	*p = *(*Provider)(t.Alias)
	return nil
}
