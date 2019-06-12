package identity // import "github.com/pomerium/pomerium/internal/identity"

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

	oidc "github.com/pomerium/go-oidc"
	"golang.org/x/oauth2"

	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/version"
)

// OktaProvider represents the Okta Identity Provider
//
// https://www.pomerium.io/docs/identity-providers.html#okta
type OktaProvider struct {
	*Provider

	RevokeURL *url.URL
}

// NewOktaProvider creates a new instance of Okta as an identity provider.
func NewOktaProvider(p *Provider) (*OktaProvider, error) {
	ctx := context.Background()
	if p.ProviderURL == "" {
		return nil, ErrMissingProviderURL
	}
	var err error
	p.provider, err = oidc.NewProvider(ctx, p.ProviderURL)
	if err != nil {
		return nil, err
	}
	if len(p.Scopes) == 0 {
		p.Scopes = []string{oidc.ScopeOpenID, "profile", "email", "groups", "offline_access"}
	}
	p.verifier = p.provider.Verifier(&oidc.Config{ClientID: p.ClientID})
	p.oauth = &oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: p.ClientSecret,
		Endpoint:     p.provider.Endpoint(),
		RedirectURL:  p.RedirectURL.String(),
		Scopes:       p.Scopes,
	}

	// okta supports a revocation endpoint
	var claims struct {
		RevokeURL string `json:"revocation_endpoint"`
	}
	if err := p.provider.Claims(&claims); err != nil {
		return nil, err
	}
	oktaProvider := OktaProvider{Provider: p}

	oktaProvider.RevokeURL, err = url.Parse(claims.RevokeURL)
	if err != nil {
		return nil, err
	}
	return &oktaProvider, nil
}

// Revoke revokes the access token a given session state.
// https://developer.okta.com/docs/api/resources/oidc#revoke
func (p *OktaProvider) Revoke(token string) error {
	params := url.Values{}
	params.Add("client_id", p.ClientID)
	params.Add("client_secret", p.ClientSecret)
	params.Add("token", token)
	params.Add("token_type_hint", "refresh_token")
	err := httputil.Client(http.MethodPost, p.RevokeURL.String(), version.UserAgent(), nil, params, nil)
	if err != nil && err != httputil.ErrTokenRevoked {
		return err
	}
	return nil
}

type accessToken struct {
	Subject string   `json:"sub"`
	Groups  []string `json:"groups"`
}

// Refresh renews a user's session using an oid refresh token without reprompting the user.
// Group membership is also refreshed. If configured properly, Okta is we can configure the access token
// to include group membership claims which allows us to avoid a follow up oauth2 call.
func (p *OktaProvider) Refresh(ctx context.Context, s *sessions.SessionState) (*sessions.SessionState, error) {
	if s.RefreshToken == "" {
		return nil, errors.New("identity/okta: missing refresh token")
	}
	t := oauth2.Token{RefreshToken: s.RefreshToken}
	newToken, err := p.oauth.TokenSource(ctx, &t).Token()
	if err != nil {
		log.Error().Err(err).Msg("identity/okta: refresh failed")
		return nil, err
	}

	payload, err := parseJWT(newToken.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("identity/okta: malformed access token jwt: %v", err)
	}
	var token accessToken
	if err := json.Unmarshal(payload, &token); err != nil {
		return nil, fmt.Errorf("identity/okta: failed to unmarshal access token claims: %v", err)
	}
	if len(token.Groups) != 0 {
		s.Groups = token.Groups
	}

	s.AccessToken = newToken.AccessToken
	s.RefreshDeadline = newToken.Expiry.Truncate(time.Second)
	return s, nil
}

func parseJWT(p string) ([]byte, error) {
	parts := strings.Split(p, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("oidc: malformed jwt, expected 3 parts got %d", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("oidc: malformed jwt payload: %v", err)
	}
	return payload, nil
}
