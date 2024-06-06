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
	"sync"

	go_oidc "github.com/coreos/go-oidc/v3/oidc"
	"go.opentelemetry.io/otel/codes"
	"golang.org/x/oauth2"

	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/internal/version"
	"github.com/pomerium/pomerium/pkg/identity/identity"
	"github.com/pomerium/pomerium/pkg/identity/oauth"
)

// Name identifies the generic OpenID Connect provider.
const Name = "oidc"

var defaultScopes = []string{go_oidc.ScopeOpenID, "profile", "email", "offline_access"}

var defaultAuthCodeOptions = []oauth2.AuthCodeOption{}

// Provider provides a standard, OpenID Connect implementation
// of an authorization identity provider.
// https://openid.net/specs/openid-connect-core-1_0.html
type Provider struct {
	cfg *config

	// RevocationURL is the location of the OAuth 2.0 token revocation endpoint.
	// https://tools.ietf.org/html/rfc7009
	RevocationURL string `json:"revocation_endpoint,omitempty"`

	// EndSessionURL is another endpoint that can be used by other identity
	// providers that doesn't implement the revocation endpoint but a logout session.
	// https://openid.net/specs/openid-connect-frontchannel-1_0.html#RPInitiated
	EndSessionURL string `json:"end_session_endpoint,omitempty"`

	// AuthCodeOptions specifies additional key value pairs query params to add
	// to the request flow signin url.
	AuthCodeOptions map[string]string

	DeviceAuthClientType string

	mu       sync.Mutex
	provider *go_oidc.Provider
}

// New creates a new instance of a generic OpenID Connect provider.
func New(ctx context.Context, o *oauth.Options, options ...Option) (*Provider, error) {
	if o.ProviderURL == "" {
		return nil, ErrMissingProviderURL
	}

	p := new(Provider)
	if len(o.Scopes) == 0 {
		o.Scopes = defaultScopes
	}
	if len(o.AuthCodeOptions) != 0 {
		p.AuthCodeOptions = o.AuthCodeOptions
	}
	if o.DeviceAuthClientType != "" {
		p.DeviceAuthClientType = o.DeviceAuthClientType
	}

	p.cfg = getConfig(append([]Option{
		WithGetOauthConfig(func(provider *go_oidc.Provider) *oauth2.Config {
			return &oauth2.Config{
				ClientID:     o.ClientID,
				ClientSecret: o.ClientSecret,
				Scopes:       o.Scopes,
				Endpoint:     provider.Endpoint(),
				RedirectURL:  o.RedirectURL.String(),
			}
		}),
		WithGetProvider(func() (*go_oidc.Provider, error) {
			pp, err := go_oidc.NewProvider(ctx, o.ProviderURL)
			if err != nil {
				return nil, fmt.Errorf("identity/oidc: could not connect to %s: %w", o.ProviderName, err)
			}

			// add non-standard claims like end-session, revoke, and user info
			if err := pp.Claims(&p); err != nil {
				return nil, fmt.Errorf("identity/oidc: could not retrieve additional claims: %w", err)
			}

			return pp, nil
		}),
		WithGetVerifier(func(provider *go_oidc.Provider) *go_oidc.IDTokenVerifier {
			return provider.Verifier(&go_oidc.Config{ClientID: o.ClientID})
		}),
	}, options...)...)
	return p, nil
}

// SignIn redirects to the url of the provider's OAuth 2.0 consent page
// that asks for permissions for the required scopes explicitly.
//
// State is a token to protect the user from CSRF attacks. You must
// always provide a non-empty string and validate that it matches the
// the state query parameter on your redirect callback.
// See http://tools.ietf.org/html/rfc6749#section-10.12 for more info.
func (p *Provider) SignIn(w http.ResponseWriter, r *http.Request, state string) error {
	_, span := trace.Continue(r.Context(), "oidc: sign in")
	defer span.End()

	oa, err := p.GetOauthConfig()
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	opts := defaultAuthCodeOptions
	for k, v := range p.AuthCodeOptions {
		opts = append(opts, oauth2.SetAuthURLParam(k, v))
	}
	signInURL := oa.AuthCodeURL(state, opts...)
	httputil.Redirect(w, r, signInURL, http.StatusFound)
	return nil
}

func (p *Provider) DeviceAuth(w http.ResponseWriter, r *http.Request) (*oauth2.DeviceAuthResponse, error) {
	oa, err := p.GetOauthConfig()
	if err != nil {
		return nil, err
	}

	opts := defaultAuthCodeOptions
	for k, v := range p.AuthCodeOptions {
		opts = append(opts, oauth2.SetAuthURLParam(k, v))
	}
	switch p.DeviceAuthClientType {
	case "", "public":
	case "confidential":
		opts = append(opts, oauth2.SetAuthURLParam("client_secret", oa.ClientSecret))
	}

	resp, err := oa.DeviceAuth(r.Context(), opts...)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func (p *Provider) DeviceAccessToken(ctx context.Context, da *oauth2.DeviceAuthResponse, v identity.State) (*oauth2.Token, error) {
	oa, err := p.GetOauthConfig()
	if err != nil {
		return nil, err
	}

	oauth2Token, err := oa.DeviceAccessToken(ctx, da)
	if err != nil {
		return nil, err
	}

	//
	// TODO: the rest of this function is copied from Authenticate
	//

	idToken, err := p.getIDToken(ctx, oauth2Token)
	if err != nil {
		return nil, fmt.Errorf("identity/oidc: failed getting id_token: %w", err)
	}

	if rawIDToken, ok := oauth2Token.Extra("id_token").(string); ok {
		v.SetRawIDToken(rawIDToken)
	}

	// hydrate `v` using claims inside the returned `id_token`
	// https://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint
	if err := idToken.Claims(v); err != nil {
		return nil, fmt.Errorf("identity/oidc: couldn't unmarshal extra claims %w", err)
	}

	if err := p.UpdateUserInfo(ctx, oauth2Token, v); err != nil {
		return nil, fmt.Errorf("identity/oidc: couldn't update user info %w", err)
	}

	return oauth2Token, nil
}

// Authenticate converts an authorization code returned from the identity
// provider into a token which is then converted into a user session.
func (p *Provider) Authenticate(ctx context.Context, code string, v identity.State) (*oauth2.Token, error) {
	ctx, span := trace.Continue(ctx, "oidc: authenticate")
	defer span.End()

	oauth2Token, idToken, err := p.exchange(ctx, code)
	if err != nil {
		return nil, err
	}

	if rawIDToken, ok := oauth2Token.Extra("id_token").(string); ok {
		v.SetRawIDToken(rawIDToken)
	}

	// hydrate `v` using claims inside the returned `id_token`
	// https://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint
	if err := idToken.Claims(v); err != nil {
		err := fmt.Errorf("identity/oidc: couldn't unmarshal extra claims %w", err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	if err := p.UpdateUserInfo(ctx, oauth2Token, v); err != nil {
		err := fmt.Errorf("identity/oidc: couldn't update user info %w", err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	return oauth2Token, nil
}

func (p *Provider) exchange(ctx context.Context, code string) (*oauth2.Token, *go_oidc.IDToken, error) {
	ctx, span := trace.Continue(ctx, "oidc: token exchange")
	defer span.End()

	oa, err := p.GetOauthConfig()
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, nil, err
	}

	// Exchange converts an authorization code into a token.
	oauth2Token, err := oa.Exchange(ctx, code)
	if err != nil {
		err := fmt.Errorf("identity/oidc: token exchange failed: %w", err)
		span.SetStatus(codes.Error, err.Error())
		return nil, nil, err
	}

	idToken, err := p.getIDToken(ctx, oauth2Token)
	if err != nil {
		err := fmt.Errorf("identity/oidc: failed getting id_token: %w", err)
		span.SetStatus(codes.Error, err.Error())
		return nil, nil, err
	}

	return oauth2Token, idToken, nil
}

// UpdateUserInfo calls the OIDC (spec required) UserInfo Endpoint as well as any
// groups endpoint (non-spec) to populate the rest of the user's information.
//
// https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
func (p *Provider) UpdateUserInfo(ctx context.Context, t *oauth2.Token, v any) error {
	ctx, span := trace.Continue(ctx, "oidc: update user info")
	defer span.End()

	pp, err := p.GetProvider()
	if err != nil {
		return err
	}

	userInfo, err := getUserInfo(ctx, pp, oauth2.StaticTokenSource(t))
	if err != nil {
		return fmt.Errorf("identity/oidc: user info endpoint: %w", err)
	}
	if err := userInfo.Claims(v); err != nil {
		return fmt.Errorf("identity/oidc: failed parsing user info endpoint claims: %w", err)
	}
	return nil
}

// Refresh renews a user's session using an oidc refresh token without reprompting the user.
// Group membership is also refreshed.
// https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokens
func (p *Provider) Refresh(ctx context.Context, t *oauth2.Token, v identity.State) (*oauth2.Token, error) {
	oa, err := p.GetOauthConfig()
	if err != nil {
		return nil, err
	}

	newToken, err := Refresh(ctx, oa, t)
	if err != nil {
		return nil, err
	}

	// Many identity providers _will not_ return `id_token` on refresh
	// https://github.com/FusionAuth/fusionauth-issues/issues/110#issuecomment-481526544
	idToken, err := p.getIDToken(ctx, newToken)
	if err == nil {
		if rawIDToken, ok := newToken.Extra("id_token").(string); ok {
			v.SetRawIDToken(rawIDToken)
		}

		if err := idToken.Claims(v); err != nil {
			return nil, fmt.Errorf("identity/oidc: couldn't unmarshal extra claims %w", err)
		}
	}
	return newToken, nil
}

// getIDToken returns the raw jwt payload for `id_token` from the oauth2 token
// returned following oidc code flow
//
// https://openid.net/specs/openid-connect-core-1_0.html#TokenResponse
func (p *Provider) getIDToken(ctx context.Context, t *oauth2.Token) (*go_oidc.IDToken, error) {
	v, err := p.GetVerifier()
	if err != nil {
		return nil, err
	}

	rawIDToken, ok := t.Extra("id_token").(string)
	if !ok {
		return nil, ErrMissingIDToken
	}
	return v.Verify(ctx, rawIDToken)
}

// Revoke enables a user to revoke her token. If the identity provider does not
// support revocation an error is thrown.
//
// https://tools.ietf.org/html/rfc7009#section-2.1
func (p *Provider) Revoke(ctx context.Context, t *oauth2.Token) error {
	oa, err := p.GetOauthConfig()
	if err != nil {
		return err
	}

	if p.RevocationURL == "" {
		return ErrRevokeNotImplemented
	}
	if t == nil {
		return ErrMissingAccessToken
	}

	params := url.Values{}
	params.Add("token", t.AccessToken)
	params.Add("token_type_hint", "access_token")
	// Some providers like okta / onelogin require "client authentication"
	// https://developer.okta.com/docs/reference/api/oidc/#client-secret
	// https://developers.onelogin.com/openid-connect/api/revoke-session
	params.Add("client_id", oa.ClientID)
	params.Add("client_secret", oa.ClientSecret)

	err = httputil.Do(ctx, http.MethodPost, p.RevocationURL, version.UserAgent(), nil, params, nil)
	if err != nil && errors.Is(err, httputil.ErrTokenRevoked) {
		return fmt.Errorf("internal/oidc: unexpected revoke error: %w", err)
	}

	return nil
}

// Name returns the provider name.
func (p *Provider) Name() string {
	return Name
}

// GetProvider gets the underlying oidc Provider.
func (p *Provider) GetProvider() (*go_oidc.Provider, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.provider != nil {
		return p.provider, nil
	}

	pp, err := p.cfg.getProvider()
	if err != nil {
		return nil, err
	}
	p.provider = pp
	return pp, nil
}

// GetVerifier gets the verifier.
func (p *Provider) GetVerifier() (*go_oidc.IDTokenVerifier, error) {
	pp, err := p.GetProvider()
	if err != nil {
		return nil, err
	}
	return p.cfg.getVerifier(pp), nil
}

// GetOauthConfig gets the oauth.
func (p *Provider) GetOauthConfig() (*oauth2.Config, error) {
	pp, err := p.GetProvider()
	if err != nil {
		return nil, err
	}
	return p.cfg.getOauthConfig(pp), nil
}

// SignOut uses the EndSessionURL endpoint to allow a logout session to be initiated.
// https://openid.net/specs/openid-connect-frontchannel-1_0.html#RPInitiated
func (p *Provider) SignOut(w http.ResponseWriter, r *http.Request, idTokenHint, authenticateSignedOutURL, redirectToURL string) error {
	_, err := p.GetProvider()
	if err != nil {
		return err
	}

	if p.EndSessionURL == "" {
		return ErrSignoutNotImplemented
	}

	endSessionURL, err := urlutil.ParseAndValidateURL(p.EndSessionURL)
	if err != nil {
		return err
	}

	params := endSessionURL.Query()
	if idTokenHint != "" {
		params.Add("id_token_hint", idTokenHint)
	}
	if oa, err := p.GetOauthConfig(); err == nil {
		params.Add("client_id", oa.ClientID)
	}
	if redirectToURL != "" {
		params.Add("post_logout_redirect_uri", redirectToURL)
	} else if authenticateSignedOutURL != "" {
		params.Add("post_logout_redirect_uri", authenticateSignedOutURL)
	}
	endSessionURL.RawQuery = params.Encode()

	httputil.Redirect(w, r, endSessionURL.String(), http.StatusFound)
	return nil
}
