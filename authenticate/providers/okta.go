package providers // import "github.com/pomerium/pomerium/internal/providers"

import (
	"context"
	"errors"
	"net/url"

	oidc "github.com/pomerium/go-oidc"
	"golang.org/x/oauth2"

	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/version"
)

// OktaProvider provides a standard, OpenID Connect implementation
// of an authorization identity provider.
type OktaProvider struct {
	*ProviderData

	// non-standard oidc fields
	RevokeURL *url.URL
}

// NewOktaProvider creates a new instance of an OpenID Connect provider.
func NewOktaProvider(p *ProviderData) (*OktaProvider, error) {
	ctx := context.Background()
	if p.ProviderURL == "" {
		return nil, errors.New("missing required provider url")
	}
	var err error
	p.provider, err = oidc.NewProvider(ctx, p.ProviderURL)
	if err != nil {
		return nil, err
	}
	p.verifier = p.provider.Verifier(&oidc.Config{ClientID: p.ClientID})
	p.oauth = &oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: p.ClientSecret,
		Endpoint:     p.provider.Endpoint(),
		RedirectURL:  p.RedirectURL.String(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}
	oktaProvider := OktaProvider{ProviderData: p}

	// okta supports a revocation endpoint
	var claims struct {
		RevokeURL string `json:"revocation_endpoint"`
	}

	if err := p.provider.Claims(&claims); err != nil {
		return nil, err
	}

	oktaProvider.RevokeURL, err = url.Parse(claims.RevokeURL)
	if err != nil {
		return nil, err
	}
	return &oktaProvider, nil
}

// Revoke revokes the access token a given session state.
// https://developer.okta.com/docs/api/resources/oidc#revoke
func (p *OktaProvider) Revoke(s *sessions.SessionState) error {
	params := url.Values{}
	params.Add("client_id", p.ClientID)
	params.Add("client_secret", p.ClientSecret)
	params.Add("token", s.IDToken)
	params.Add("token_type_hint", "refresh_token")
	err := httputil.Client("POST", p.RevokeURL.String(), version.UserAgent(), params, nil)
	if err != nil && err != httputil.ErrTokenRevoked {
		return err
	}
	return nil
}
