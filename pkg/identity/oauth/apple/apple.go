// Package apple implements OpenID Connect for apple
//
// https://www.pomerium.com/docs/identity-providers/apple
package apple

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-jose/go-jose/v3/jwt"
	"golang.org/x/oauth2"

	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/internal/version"
	"github.com/pomerium/pomerium/pkg/identity/identity"
	"github.com/pomerium/pomerium/pkg/identity/oauth"
	"github.com/pomerium/pomerium/pkg/identity/oidc"
)

// Name identifies the apple identity provider.
const Name = "apple"

const (
	defaultProviderURL = "https://appleid.apple.com"
	tokenURL           = "/auth/token" //nolint: gosec
	authURL            = "/auth/authorize"
	revocationURL      = "/auth/revoke"
)

var (
	defaultScopes          = []string{"name", "email"}
	defaultAuthCodeOptions = map[string]string{
		"response_mode": "form_post",
	}
)

// Provider is an Apple implementation of the Authenticator interface.
type Provider struct {
	oauth           *oauth2.Config
	authCodeOptions map[string]string
}

// New instantiates an OpenID Connect (OIDC) provider for Apple.
func New(_ context.Context, o *oauth.Options) (*Provider, error) {
	options := *o
	if options.ProviderURL == "" {
		options.ProviderURL = defaultProviderURL
	}
	if len(options.Scopes) == 0 {
		options.Scopes = defaultScopes
	}

	p := Provider{}
	p.authCodeOptions = make(map[string]string)
	maps.Copy(p.authCodeOptions, defaultAuthCodeOptions)
	maps.Copy(p.authCodeOptions, options.AuthCodeOptions)

	// Apple expects the AuthStyle to use Params instead of Headers
	// So we have to do our own oauth2 config
	p.oauth = &oauth2.Config{
		ClientID:     options.ClientID,
		ClientSecret: options.ClientSecret,
		Scopes:       options.Scopes,
		RedirectURL:  options.RedirectURL.String(),
		Endpoint: oauth2.Endpoint{
			AuthURL:   urlutil.Join(options.ProviderURL, authURL),
			TokenURL:  urlutil.Join(options.ProviderURL, tokenURL),
			AuthStyle: oauth2.AuthStyleInParams,
		},
	}

	return &p, nil
}

// Name returns the provider name.
func (p *Provider) Name() string {
	return Name
}

// Authenticate converts an authorization code returned from the identity
// provider into a token which is then converted into a user session.
func (p *Provider) Authenticate(ctx context.Context, code string, v identity.State) (*oauth2.Token, error) {
	oauth2Token, err := p.oauth.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("identity/apple: token exchange failed: %w", err)
	}

	if rawIDToken, ok := oauth2Token.Extra("id_token").(string); ok {
		v.SetRawIDToken(rawIDToken)
	}

	err = p.UpdateUserInfo(ctx, oauth2Token, v)
	if err != nil {
		return nil, err
	}

	return oauth2Token, nil
}

// Refresh renews a user's session.
func (p *Provider) Refresh(ctx context.Context, t *oauth2.Token, v identity.State) (*oauth2.Token, error) {
	newToken, err := oidc.Refresh(ctx, p.oauth, t)
	if err != nil {
		return nil, err
	}

	if rawIDToken, ok := newToken.Extra("id_token").(string); ok {
		v.SetRawIDToken(rawIDToken)
	}

	err = p.UpdateUserInfo(ctx, newToken, v)
	if err != nil {
		return nil, err
	}

	return newToken, nil
}

// Revoke method will remove all the Apple grants the user gave pomerium application during authorization.
func (p *Provider) Revoke(ctx context.Context, t *oauth2.Token) error {
	if t == nil {
		return oidc.ErrMissingAccessToken
	}

	params := url.Values{}
	params.Add("token", t.AccessToken)
	params.Add("token_type_hint", "access_token")
	params.Add("client_id", p.oauth.ClientID)
	params.Add("client_secret", p.oauth.ClientSecret)

	err := httputil.Do(ctx, http.MethodPost, revocationURL, version.UserAgent(), nil, params, nil)
	if err != nil && errors.Is(err, httputil.ErrTokenRevoked) {
		return fmt.Errorf("identity/apple: unexpected revoke error: %w", err)
	}

	return nil
}

// UpdateUserInfo gets claims from the oauth token.
func (p *Provider) UpdateUserInfo(_ context.Context, t *oauth2.Token, v any) error {
	rawIDToken, ok := t.Extra("id_token").(string)
	if !ok {
		return nil
	}

	idToken, err := jwt.ParseSigned(rawIDToken)
	if err != nil {
		return err
	}

	return idToken.UnsafeClaimsWithoutVerification(v)
}

// SignIn redirects to the url of the provider's OAuth 2.0 consent page
// that asks for permissions for the required scopes explicitly.
//
// State is a token to protect the user from CSRF attacks. You must
// always provide a non-empty string and validate that it matches the
// the state query parameter on your redirect callback.
// See http://tools.ietf.org/html/rfc6749#section-10.12 for more info.
func (p *Provider) SignIn(w http.ResponseWriter, r *http.Request, state string) error {
	opts := []oauth2.AuthCodeOption{}
	for k, v := range p.authCodeOptions {
		opts = append(opts, oauth2.SetAuthURLParam(k, v))
	}
	authURL := p.oauth.AuthCodeURL(state, opts...)

	// Apple is very picky here and we need to use %20 instead of +
	authURL = strings.ReplaceAll(authURL, "+", "%20")

	httputil.Redirect(w, r, authURL, http.StatusFound)
	return nil
}

// SignOut is not implemented.
func (p *Provider) SignOut(_ http.ResponseWriter, _ *http.Request, _, _, _ string) error {
	return oidc.ErrSignoutNotImplemented
}

// VerifyAccessToken verifies an access token.
func (p *Provider) VerifyAccessToken(_ context.Context, _ string) (claims map[string]any, err error) {
	return nil, identity.ErrVerifyAccessTokenNotSupported
}

// VerifyIdentityToken verifies an identity token.
func (p *Provider) VerifyIdentityToken(_ context.Context, _ string) (claims map[string]any, err error) {
	return nil, identity.ErrVerifyIdentityTokenNotSupported
}
