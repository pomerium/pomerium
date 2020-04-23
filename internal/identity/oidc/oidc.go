// Package oidc implements a generic OpenID Connect provider.
//
// https://openid.net/specs/openid-connect-core-1_0.html
package oidc

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	go_oidc "github.com/coreos/go-oidc"
	"golang.org/x/oauth2"

	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/identity/oauth"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/internal/version"
)

// Name identifies the generic OpenID Connect provider
const Name = "oidc"

var defaultScopes = []string{go_oidc.ScopeOpenID, "profile", "email", "offline_access"}

// Provider provides a standard, OpenID Connect implementation
// of an authorization identity provider.
// https://openid.net/specs/openid-connect-core-1_0.html
type Provider struct {
	// Provider represents an OpenID Connect server's configuration.
	Provider *go_oidc.Provider
	// Verifier provides verification for ID Tokens.
	Verifier *go_oidc.IDTokenVerifier
	// Oauth describes a typical 3-legged OAuth2 flow, with both the
	// client application information and the server's endpoint URLs.
	Oauth *oauth2.Config

	// UserInfoURL specifies the endpoint responsible for returning claims
	// about the authenticated End-User.
	// https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
	UserInfoURL string `json:"userinfo_endpoint,omitempty"`

	// RevocationURL is the location of the OAuth 2.0 token revocation endpoint.
	// https://tools.ietf.org/html/rfc7009
	RevocationURL string `json:"revocation_endpoint,omitempty"`

	// EndSessionURL is another endpoint that can be used by other identity
	// providers that doesn't implement the revocation endpoint but a logout session.
	// https://openid.net/specs/openid-connect-frontchannel-1_0.html#RPInitiated
	EndSessionURL string `json:"end_session_endpoint,omitempty"`

	// UserGroupFn is, if set, used to return a slice of group IDs the
	// user is a member of
	UserGroupFn func(context.Context, *sessions.State) ([]string, error)
}

// New creates a new instance of a generic OpenID Connect provider.
func New(ctx context.Context, o *oauth.Options) (*Provider, error) {
	var err error
	var p Provider
	if o.ProviderURL == "" {
		return nil, ErrMissingProviderURL
	}
	if len(o.Scopes) == 0 {
		o.Scopes = defaultScopes
	}
	p.Provider, err = go_oidc.NewProvider(ctx, o.ProviderURL)
	if err != nil {
		return nil, fmt.Errorf("identity/oidc: could not connect to %s: %w", o.ProviderName, err)
	}

	p.Verifier = p.Provider.Verifier(&go_oidc.Config{ClientID: o.ClientID})
	p.Oauth = &oauth2.Config{
		ClientID:     o.ClientID,
		ClientSecret: o.ClientSecret,
		Scopes:       o.Scopes,
		Endpoint:     p.Provider.Endpoint(),
		RedirectURL:  o.RedirectURL.String(),
	}

	// add non-standard claims like end-session, revoke, and user info
	if err := p.Provider.Claims(&p); err != nil {
		return nil, fmt.Errorf("identity/oidc: could not retrieve additional claims: %w", err)
	}
	return &p, nil
}

// GetSignInURL returns the url of the provider's OAuth 2.0 consent page
// that asks for permissions for the required scopes explicitly.
//
// State is a token to protect the user from CSRF attacks. You must
// always provide a non-empty string and validate that it matches the
// the state query parameter on your redirect callback.
// See http://tools.ietf.org/html/rfc6749#section-10.12 for more info.
func (p *Provider) GetSignInURL(state string) string {
	return p.Oauth.AuthCodeURL(state, oauth2.AccessTypeOffline)
}

// Authenticate converts an authorization code returned from the identity
// provider into a token which is then converted into a user session.
func (p *Provider) Authenticate(ctx context.Context, code string) (*sessions.State, error) {
	oauth2Token, err := p.Oauth.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("identity/oidc: token exchange failed: %w", err)
	}
	idToken, err := p.IdentityFromToken(ctx, oauth2Token)
	if err != nil {
		return nil, fmt.Errorf("identity/oidc: failed getting id_token: %w", err)
	}

	aud, err := urlutil.ParseAndValidateURL(p.Oauth.RedirectURL)
	if err != nil {
		return nil, fmt.Errorf("identity/oidc: bad redirect uri: %w", err)
	}

	s, err := sessions.NewStateFromTokens(idToken, oauth2Token, aud.Hostname())
	if err != nil {
		return nil, err
	}

	if err := p.Provider.Claims(&p); err == nil && p.UserInfoURL != "" {
		userInfo, err := p.Provider.UserInfo(ctx, oauth2.StaticTokenSource(oauth2Token))
		if err != nil {
			return nil, fmt.Errorf("identity/oidc: could not retrieve user info %w", err)
		}
		if err := userInfo.Claims(&s); err != nil {
			return nil, fmt.Errorf("identity/oidc: could not parse user claims %w", err)
		}
	}

	if p.UserGroupFn != nil {
		s.Groups, err = p.UserGroupFn(ctx, s)
		if err != nil {
			return nil, fmt.Errorf("internal/oidc: could not retrieve groups %w", err)
		}
	}
	return s, nil
}

// Refresh renews a user's session using an oidc refresh token without reprompting the user.
// Group membership is also refreshed.
// https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokens
func (p *Provider) Refresh(ctx context.Context, s *sessions.State) (*sessions.State, error) {
	if s.AccessToken == nil || s.AccessToken.RefreshToken == "" {
		return nil, errors.New("internal/oidc: missing refresh token")
	}

	t := oauth2.Token{RefreshToken: s.AccessToken.RefreshToken}
	oauthToken, err := p.Oauth.TokenSource(ctx, &t).Token()
	if err != nil {
		return nil, fmt.Errorf("internal/oidc: refresh failed %w", err)
	}
	idToken, err := p.IdentityFromToken(ctx, oauthToken)
	if err != nil {
		return nil, fmt.Errorf("identity/oidc: failed getting id_token: %w", err)
	}
	if err := s.UpdateState(idToken, oauthToken); err != nil {
		return nil, fmt.Errorf("internal/oidc: state update failed %w", err)
	}
	if p.UserGroupFn != nil {
		s.Groups, err = p.UserGroupFn(ctx, s)
		if err != nil {
			return nil, fmt.Errorf("internal/oidc: could not retrieve groups %w", err)
		}
	}
	return s, nil
}

// IdentityFromToken takes an identity provider issued JWT as input ('id_token')
// and returns a session state. The provided token's audience ('aud') must
// match Pomerium's client_id.
func (p *Provider) IdentityFromToken(ctx context.Context, t *oauth2.Token) (*go_oidc.IDToken, error) {
	rawIDToken, ok := t.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("internal/oidc: id_token not found")
	}
	return p.Verifier.Verify(ctx, rawIDToken)
}

// Revoke enables a user to revoke her token. If the identity provider does not
// support revocation an error is thrown.
//
// https://tools.ietf.org/html/rfc7009#section-2.1
func (p *Provider) Revoke(ctx context.Context, token *oauth2.Token) error {
	if p.RevocationURL == "" {
		return ErrRevokeNotImplemented
	}

	params := url.Values{}
	params.Add("token", token.AccessToken)
	params.Add("token_type_hint", "access_token")
	// Some providers like okta / onelogin require "client authentication"
	// https://developer.okta.com/docs/reference/api/oidc/#client-secret
	// https://developers.onelogin.com/openid-connect/api/revoke-session
	params.Add("client_id", p.Oauth.ClientID)
	params.Add("client_secret", p.Oauth.ClientSecret)

	err := httputil.Client(ctx, http.MethodPost, p.RevocationURL, version.UserAgent(), nil, params, nil)
	if err != nil && err != httputil.ErrTokenRevoked {
		return fmt.Errorf("internal/oidc: unexpected revoke error: %w", err)
	}

	return nil
}

// LogOut returns the EndSessionURL endpoint to allow a logout
// session to be initiated.
// https://openid.net/specs/openid-connect-frontchannel-1_0.html#RPInitiated
func (p *Provider) LogOut() (*url.URL, error) {
	if p.EndSessionURL == "" {
		return nil, ErrSignoutNotImplemented
	}
	return urlutil.ParseAndValidateURL(p.EndSessionURL)
}
