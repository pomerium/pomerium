package providers // import "github.com/pomerium/pomerium/internal/providers"

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
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
)

// Provider is an interface exposing functions necessary to interact with a given provider.
type Provider interface {
	Data() *ProviderData
	Redeem(string) (*sessions.SessionState, error)
	ValidateSessionState(*sessions.SessionState) bool
	GetSignInURL(state string) string
	RefreshSessionIfNeeded(*sessions.SessionState) (bool, error)
	Revoke(*sessions.SessionState) error
	RefreshAccessToken(string) (string, time.Duration, error)
}

// New returns a new identity provider based given its name.
// Returns an error if selected provided not found or if the provider fails to instantiate.
func New(provider string, pd *ProviderData) (Provider, error) {
	var err error
	var p Provider
	switch provider {
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
	default:
		return nil, fmt.Errorf("authenticate: provider %q not found", provider)
	}
	if err != nil {
		return nil, err
	}
	return p, nil
}

// ProviderData holds the fields associated with providers
// necessary to implement the Provider interface.
type ProviderData struct {
	RedirectURL        *url.URL
	ProviderName       string
	ClientID           string
	ClientSecret       string
	ProviderURL        string
	Scopes             []string
	SessionLifetimeTTL time.Duration

	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
	oauth    *oauth2.Config
}

// Data returns a ProviderData.
func (p *ProviderData) Data() *ProviderData { return p }

// GetSignInURL returns the sign in url with typical oauth parameters
func (p *ProviderData) GetSignInURL(state string) string {
	return p.oauth.AuthCodeURL(state)
}

// ValidateSessionState validates a given session's from it's JWT token
// The function verifies it's been signed by the provider, preforms
// any additional checks depending on the Config, and returns the payload.
//
// ValidateSessionState does NOT do nonce validation.
func (p *ProviderData) ValidateSessionState(s *sessions.SessionState) bool {
	ctx := context.Background()
	_, err := p.verifier.Verify(ctx, s.IDToken)
	if err != nil {
		log.Error().Err(err).Msg("authenticate/providers: failed to verify session state")
		return false
	}
	return true
}

// Redeem creates a session with an identity provider from a authorization code
func (p *ProviderData) Redeem(code string) (*sessions.SessionState, error) {
	ctx := context.Background()
	// convert authorization code into a token
	token, err := p.oauth.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("authenticate/providers: failed token exchange: %v", err)
	}
	s, err := p.createSessionState(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("authenticate/providers: unable to update session: %v", err)
	}

	// check if provider has info endpoint, try to hit that and gather more info
	// especially useful if initial request did not contain email
	// https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
	var claims struct {
		UserInfoURL string `json:"userinfo_endpoint"`
	}

	if err := p.provider.Claims(&claims); err != nil || claims.UserInfoURL == "" {
		log.Error().Err(err).Msg("authenticate/providers: failed retrieving userinfo_endpoint")
	} else {
		// userinfo endpoint found and valid
		userInfo, err := p.UserInfo(ctx, claims.UserInfoURL, oauth2.StaticTokenSource(token))
		if err != nil {
			return nil, fmt.Errorf("authenticate/providers: can't parse userinfo_endpoint: %v", err)
		}
		s.Email = userInfo.Email
	}

	return s, nil
}

// RefreshSessionIfNeeded will refresh the session state if it's deadline is expired
func (p *ProviderData) RefreshSessionIfNeeded(s *sessions.SessionState) (bool, error) {
	if !sessionRefreshRequired(s) {
		log.Debug().Msg("authenticate/providers: session refresh not needed")
		return false, nil
	}
	origExpiration := s.RefreshDeadline
	err := p.redeemRefreshToken(s)
	if err != nil {
		return false, fmt.Errorf("authenticate/providers: couldn't refresh token: %v", err)
	}

	log.Debug().Time("NewDeadline", s.RefreshDeadline).Time("OldDeadline", origExpiration).Msgf("authenticate/providers refreshed")
	return true, nil
}

func (p *ProviderData) redeemRefreshToken(s *sessions.SessionState) error {
	log.Info().Msg("authenticate/providers.oidc.redeemRefreshToken 1")
	ctx := context.Background()
	t := &oauth2.Token{
		RefreshToken: s.RefreshToken,
		Expiry:       time.Now().Add(-time.Hour),
	}
	log.Info().Msg("authenticate/providers.oidc.redeemRefreshToken 3")

	// returns a TokenSource automatically refreshing it as necessary using the provided context
	token, err := p.oauth.TokenSource(ctx, t).Token()
	if err != nil {
		return fmt.Errorf("authenticate/providers: failed to get token: %v", err)
	}
	log.Info().Msg("authenticate/providers.oidc.redeemRefreshToken 4")

	newSession, err := p.createSessionState(ctx, token)
	if err != nil {
		return fmt.Errorf("authenticate/providers: unable to update session: %v", err)
	}
	s.AccessToken = newSession.AccessToken
	s.IDToken = newSession.IDToken
	s.RefreshToken = newSession.RefreshToken
	s.RefreshDeadline = newSession.RefreshDeadline
	s.Email = newSession.Email

	log.Info().
		Str("AccessToken", s.AccessToken).
		Str("IdToken", s.IDToken).
		Time("RefreshDeadline", s.RefreshDeadline).
		Str("RefreshToken", s.RefreshToken).
		Str("Email", s.Email).
		Msg("authenticate/providers.redeemRefreshToken")

	return nil
}

func (p *ProviderData) createSessionState(ctx context.Context, token *oauth2.Token) (*sessions.SessionState, error) {
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("token response did not contain an id_token")
	}

	// Parse and verify ID Token payload.
	idToken, err := p.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("authenticate/providers: could not verify id_token: %v", err)
	}

	// Extract custom claims.
	var claims struct {
		Email    string `json:"email"`
		Verified *bool  `json:"email_verified"`
	}
	// parse claims from the raw, encoded jwt token
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("authenticate/providers: failed to parse id_token claims: %v", err)
	}
	log.Debug().
		Str("AccessToken", token.AccessToken).
		Str("IDToken", rawIDToken).
		Str("claims.Email", claims.Email).
		Str("RefreshToken", token.RefreshToken).
		Str("idToken.Subject", idToken.Subject).
		Str("idToken.Nonce", idToken.Nonce).
		Str("RefreshDeadline", idToken.Expiry.String()).
		Str("LifetimeDeadline", idToken.Expiry.String()).
		Msg("authenticate/providers.createSessionState")

	return &sessions.SessionState{
		AccessToken:      token.AccessToken,
		IDToken:          rawIDToken,
		RefreshToken:     token.RefreshToken,
		RefreshDeadline:  idToken.Expiry,
		LifetimeDeadline: idToken.Expiry,
		Email:            claims.Email,
		User:             idToken.Subject,
	}, nil
}

// RefreshAccessToken allows the service to refresh an access token without
// prompting the user for permission.
func (p *ProviderData) RefreshAccessToken(refreshToken string) (string, time.Duration, error) {
	if refreshToken == "" {
		return "", 0, errors.New("authenticate/providers: missing refresh token")
	}
	ctx := context.Background()
	c := oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: p.ClientSecret,
		Endpoint:     oauth2.Endpoint{TokenURL: p.ProviderURL},
	}
	t := oauth2.Token{RefreshToken: refreshToken}
	ts := c.TokenSource(ctx, &t)
	log.Info().
		Str("RefreshToken", refreshToken).
		Msg("authenticate/providers.RefreshAccessToken")

	newToken, err := ts.Token()
	if err != nil {
		log.Error().Err(err).Msg("authenticate/providers.RefreshAccessToken")
		return "", 0, err
	}
	return newToken.AccessToken, time.Until(newToken.Expiry), nil
}

// Revoke enables a user to revoke her token. If the identity provider supports revocation
// the endpoint is available, otherwise an error is thrown.
func (p *ProviderData) Revoke(s *sessions.SessionState) error {
	return errors.New("authenticate/providers: revoke not implemented")
}

func sessionRefreshRequired(s *sessions.SessionState) bool {
	return s == nil || s.RefreshDeadline.After(time.Now()) || s.RefreshToken == ""
}

// UserInfo represents the OpenID Connect userinfo claims.
// see: https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
type UserInfo struct {
	// Stanard OIDC User fields
	Subject       string `json:"sub"`
	Profile       string `json:"profile"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	// custom claims
	Name       string   `json:"name"`        // google, gitlab
	GivenName  string   `json:"given_name"`  // google
	FamilyName string   `json:"family_name"` // google
	Picture    string   `json:"picture"`     // google,gitlab
	Locale     string   `json:"locale"`      // google
	Groups     []string `json:"groups"`      // gitlab

	claims []byte
}

// Claims unmarshals the raw JSON object claims into the provided object.
func (u *UserInfo) Claims(v interface{}) error {
	if u.claims == nil {
		return errors.New("authenticate/providers: claims not set")
	}
	return json.Unmarshal(u.claims, v)
}

// UserInfo uses the token source to query the provider's user info endpoint.
func (p *ProviderData) UserInfo(ctx context.Context, uri string, tokenSource oauth2.TokenSource) (*UserInfo, error) {
	if uri == "" {
		return nil, errors.New("authenticate/providers: user info endpoint is not supported by this provider")
	}

	req, err := http.NewRequest(http.MethodGet, uri, nil)
	if err != nil {
		return nil, fmt.Errorf("authenticate/providers: create GET request: %v", err)
	}

	token, err := tokenSource.Token()
	if err != nil {
		return nil, fmt.Errorf("authenticate/providers: get access token: %v", err)
	}
	token.SetAuthHeader(req)

	resp, err := doRequest(ctx, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", resp.Status, body)
	}

	var userInfo UserInfo
	if err := json.Unmarshal(body, &userInfo); err != nil {
		return nil, fmt.Errorf("authenticate/providers failed to decode userinfo: %v", err)
	}
	userInfo.claims = body
	return &userInfo, nil
}

func doRequest(ctx context.Context, req *http.Request) (*http.Response, error) {
	client := http.DefaultClient
	if c, ok := ctx.Value(oauth2.HTTPClient).(*http.Client); ok {
		client = c
	}
	return client.Do(req.WithContext(ctx))
}
