// Package apple implements OpenID Connect for apple
//
// https://www.pomerium.com/docs/identity-providers/apple
package apple

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"

	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/identity/identity"
	"github.com/pomerium/pomerium/internal/identity/oauth"
	"github.com/pomerium/pomerium/internal/identity/oidc"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/internal/version"
)

// Name identifies the apple identity provider.
const Name = "apple"

var defaultScopes = []string{"name", "email"}
var defaultAuthCodeOptions = map[string]string{
	"response_mode": "form_post",
}

const (
	defaultProviderURL = "https://appleid.apple.com"
	// ignore G101 linting issue as this is clearly a false positive
	tokenURL        = "/auth/token" //nolint: gosec
	authURL         = "/auth/authorize"
	refreshDeadline = time.Minute * 60
	revocationURL   = "/auth/revoke"
)

// Provider is an Apple implementation of the Authenticator interface.
type Provider struct {
	Oauth *oauth2.Config
}

// New instantiates an OpenID Connect (OIDC) provider for Apple.
func New(ctx context.Context, o *oauth.Options) (*Provider, error) {
	p := Provider{}
	if o.ProviderURL == "" {
		o.ProviderURL = defaultProviderURL
	}

	if len(o.Scopes) == 0 {
		o.Scopes = defaultScopes
	}

	// Apple expects the AuthStyle to use Params instead of Headers
	// So we have to do out own oauth2 config
	p.Oauth = &oauth2.Config{
		ClientID:     o.ClientID,
		ClientSecret: o.ClientSecret,
		Scopes:       o.Scopes,
		RedirectURL:  o.RedirectURL.String(),
		Endpoint: oauth2.Endpoint{
			AuthURL:   urlutil.Join(o.ProviderURL, authURL),
			TokenURL:  urlutil.Join(o.ProviderURL, tokenURL),
			AuthStyle: oauth2.AuthStyleInParams,
		},
	}

	return &p, nil
}

// Name returns the provider name.
func (p *Provider) Name() string {
	return Name
}

// GetSignInURL returns the url of the provider's OAuth 2.0 consent page
// that asks for permissions for the required scopes explicitly.
//
// State is a token to protect the user from CSRF attacks. You must
// always provide a non-empty string and validate that it matches the
// the state query parameter on your redirect callback.
// See http://tools.ietf.org/html/rfc6749#section-10.12 for more info.
func (p *Provider) GetSignInURL(state string) (string, error) {
	opts := []oauth2.AuthCodeOption{}
	for k, v := range defaultAuthCodeOptions {
		opts = append(opts, oauth2.SetAuthURLParam(k, v))
	}
	authURL := p.Oauth.AuthCodeURL(state, opts...)

	// Apple is very picky here and we need to use %20 instead of +
	// in order for all Apples device to correctly detect and use
	// native auth when available.
	// authURL = strings.Replace(authURL, "response_type=code", "response_type=code%20id_token", -1)
	authURL = strings.Replace(authURL, "scope=name+email", "scope=name%20email", -1)

	return authURL, nil
}

// Authenticate converts an authorization code returned from the identity
// provider into a token which is then converted into a user session.
func (p *Provider) Authenticate(ctx context.Context, code string, v identity.State) (*oauth2.Token, error) {
	oauth2Token, err := p.Oauth.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("identity/oidc: token exchange failed: %w", err)
	}

	err = p.UpdateUserInfo(ctx, oauth2Token, v)
	if err != nil {
		return nil, err
	}

	return oauth2Token, nil
}

// LogOut is not implemented by Apple.
func (p *Provider) LogOut() (*url.URL, error) {
	return nil, oidc.ErrSignoutNotImplemented
}

// Refresh renews a user's session.
func (p *Provider) Refresh(ctx context.Context, t *oauth2.Token, v identity.State) (*oauth2.Token, error) {
	if t == nil {
		return nil, oidc.ErrMissingAccessToken
	}
	if t.RefreshToken == "" {
		return nil, oidc.ErrMissingRefreshToken
	}

	newToken, err := p.Oauth.TokenSource(ctx, t).Token()
	if err != nil {
		return nil, fmt.Errorf("identity/oidc: refresh failed: %w", err)
	}

	// Many identity providers _will not_ return `id_token` on refresh
	// https://github.com/FusionAuth/fusionauth-issues/issues/110#issuecomment-481526544
	err = p.UpdateUserInfo(ctx, newToken, v)
	if err != nil {
		return nil, err
	}

	return newToken, nil
}

// Revoke method will remove all the github grants the user
// gave pomerium application during authorization.
//
// https://developer.github.com/v3/apps/oauth_applications/#delete-an-app-authorization
func (p *Provider) Revoke(ctx context.Context, t *oauth2.Token) error {
	if t == nil {
		return oidc.ErrMissingAccessToken
	}

	params := url.Values{}
	params.Add("token", t.AccessToken)
	params.Add("token_type_hint", "access_token")
	// Some providers like okta / onelogin require "client authentication"
	// https://developer.okta.com/docs/reference/api/oidc/#client-secret
	// https://developers.onelogin.com/openid-connect/api/revoke-session
	params.Add("client_id", p.Oauth.ClientID)
	params.Add("client_secret", p.Oauth.ClientSecret)

	err := httputil.Do(ctx, http.MethodPost, revocationURL, version.UserAgent(), nil, params, nil)
	if err != nil && errors.Is(err, httputil.ErrTokenRevoked) {
		return fmt.Errorf("internal/oidc: unexpected revoke error: %w", err)
	}

	return nil
}

// UpdateUserInfo will get the user information from github and also retrieve the user's team(s)
//
// https://developer.github.com/v3/users/#get-the-authenticated-user
func (p *Provider) UpdateUserInfo(ctx context.Context, t *oauth2.Token, v interface{}) error {
	rawIDToken, ok := t.Extra("id_token").(string)
	if !ok {
		return oidc.ErrMissingIDToken
	}

	v.(identity.State).SetRawIDToken(rawIDToken)

	attributes := strings.Split(rawIDToken, ".")[1]

	rawDecodedText, err := base64.RawStdEncoding.DecodeString(attributes)
	if err != nil {
		return err
	}

	err = json.Unmarshal(rawDecodedText, v)
	if err != nil {
		return err
	}

	return nil
}
