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
	// AzureProviderName identifies the Azure provider
	AzureProviderName = "azure"
	// GitlabProviderName identifies the Gitlab provider
	GitlabProviderName = "gitlab"
	// GoogleProviderName identifies the Google provider
	GoogleProviderName = "google"
	// OIDCProviderName identifes a generic OpenID connect provider
	OIDCProviderName = "oidc"
	// OktaProviderName identifes the Okta identity provider
	OktaProviderName = "okta"
)

// Provider is an interface exposing functions necessary to authenticate with a given provider.
type Provider interface {
	Data() *ProviderData
	Redeem(string) (*sessions.SessionState, error)
	ValidateSessionState(*sessions.SessionState) bool
	GetSignInURL(state string) string
	RefreshSessionIfNeeded(*sessions.SessionState) (bool, error)
	Revoke(*sessions.SessionState) error
	RefreshAccessToken(string) (string, time.Duration, error)
	// Stop()
}

// New returns a new identity provider based on available name.
// Defaults to google.
func New(provider string, p *ProviderData) (Provider, error) {
	switch provider {
	case OIDCProviderName:
		p, err := NewOIDCProvider(p)
		if err != nil {
			return nil, err
		}
		return p, nil
	case AzureProviderName:
		p, err := NewAzureProvider(p)
		if err != nil {
			return nil, err
		}
		return p, nil
	case OktaProviderName:
		p, err := NewOktaProvider(p)
		if err != nil {
			return nil, err
		}
		return p, nil
	case GitlabProviderName:
		p, err := NewGitlabProvider(p)
		if err != nil {
			return nil, err
		}
		return p, nil
	default:
		p, err := NewGoogleProvider(p)
		if err != nil {
			return nil, err
		}
		return p, nil
	}
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
		log.Error().Err(err).Msg("authenticate/providers.ValidateSessionState : failed to verify session state")
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
		log.Error().Err(err).Msg("authenticate/providers.Redeem : token exchange failed")
		return nil, fmt.Errorf("token exchange: %v", err)
	}
	s, err := p.createSessionState(ctx, token)
	if err != nil {
		log.Error().Err(err).Msg("authenticate/providers.Redeem : unable to update session")
		return nil, fmt.Errorf("unable to update session: %v", err)
	}
	return s, nil
}

// RefreshSessionIfNeeded will refresh the session state if it's deadline is expired
func (p *ProviderData) RefreshSessionIfNeeded(s *sessions.SessionState) (bool, error) {
	if !sessionRefreshRequired(s) {
		log.Info().Msg("authenticate/providers.RefreshSessionIfNeeded : session refresh not needed")
		return false, nil
	}
	origExpiration := s.RefreshDeadline
	err := p.redeemRefreshToken(s)
	if err != nil {
		log.Error().Err(err).Msg("authenticate/providers.RefreshSession")
		return false, fmt.Errorf("unable to redeem refresh token: %v", err)
	}

	log.Info().Msgf("authenticate/providers.Redeem refreshed id token %s (expired on %s)", s, origExpiration)
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
		log.Error().Err(err).Msg("authenticate/providers failed to get token")
		return fmt.Errorf("failed to get token: %v", err)
	}
	log.Info().Msg("authenticate/providers.oidc.redeemRefreshToken 4")

	newSession, err := p.createSessionState(ctx, token)
	if err != nil {
		log.Error().Err(err).Msg("authenticate/providers unable to update session")
		return fmt.Errorf("unable to update session: %v", err)
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
	log.Info().
		Bool("ctx", ctx == nil).
		Bool("Verifier", p.verifier == nil).
		Str("rawIDToken", rawIDToken).
		Msg("authenticate/providers.oidc.createSessionState 2")

	// Parse and verify ID Token payload.
	idToken, err := p.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		log.Error().Err(err).Msg("authenticate/providers could not verify id_token")
		return nil, fmt.Errorf("could not verify id_token: %v", err)
	}

	// Extract custom claims.
	var claims struct {
		Email    string `json:"email"`
		Verified *bool  `json:"email_verified"`
	}
	// parse claims from the raw, encoded jwt token
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse id_token claims: %v", err)
	}

	if claims.Email == "" {
		return nil, fmt.Errorf("id_token did not contain an email")
	}
	if claims.Verified != nil && !*claims.Verified {
		return nil, fmt.Errorf("email in id_token (%s) isn't verified", claims.Email)
	}

	return &sessions.SessionState{
		AccessToken:      token.AccessToken,
		IDToken:          rawIDToken,
		RefreshToken:     token.RefreshToken,
		RefreshDeadline:  token.Expiry,
		LifetimeDeadline: token.Expiry,
		Email:            claims.Email,
	}, nil
}

// RefreshAccessToken allows the service to refresh an access token without
// prompting the user for permission.
func (p *ProviderData) RefreshAccessToken(refreshToken string) (string, time.Duration, error) {
	if refreshToken == "" {
		return "", 0, errors.New("missing refresh token")
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
	return newToken.AccessToken, newToken.Expiry.Sub(time.Now()), nil
}

// Revoke enables a user to revoke her tokenn. Though many providers such as
// google and okta provide revoke endpoints, since it's not officially supported
// as part of OpenID Connect, the default implementation throws an error.
func (p *ProviderData) Revoke(s *sessions.SessionState) error {
	return errors.New("revoke not implemented")
}

func sessionRefreshRequired(s *sessions.SessionState) bool {
	return s == nil || s.RefreshDeadline.After(time.Now()) || s.RefreshToken == ""

}
