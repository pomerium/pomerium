package providers // import "github.com/pomerium/pomerium/internal/providers"

import (
	"context"
	"net/url"

	oidc "github.com/pomerium/go-oidc"
	"golang.org/x/oauth2"

	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/version"
)

// OktaProvider provides a standard, OpenID Connect implementation
// of an authorization identity provider.
type OktaProvider struct {
	*IdentityProvider

	// non-standard oidc fields
	RevokeURL *url.URL
}

// NewOktaProvider creates a new instance of an OpenID Connect provider.
func NewOktaProvider(p *IdentityProvider) (*OktaProvider, error) {
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
		p.Scopes = []string{oidc.ScopeOpenID, "profile", "email", "offline_access"}
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
	oktaProvider := OktaProvider{IdentityProvider: p}

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
	err := httputil.Client("POST", p.RevokeURL.String(), version.UserAgent(), params, nil)
	if err != nil && err != httputil.ErrTokenRevoked {
		return err
	}
	return nil
}

// GetSignInURL returns the sign in url with typical oauth parameters
// Google requires access type offline
func (p *OktaProvider) GetSignInURL(state string) string {
	return p.oauth.AuthCodeURL(state, oauth2.AccessTypeOffline)
}
