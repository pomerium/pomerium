package providers // import "github.com/pomerium/pomerium/internal/providers"

import (
	"context"
	"net/url"

	oidc "github.com/pomerium/go-oidc"
	"golang.org/x/oauth2"

	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/version"
)

// OneLoginProvider provides a standard, OpenID Connect implementation
// of an authorization identity provider.
type OneLoginProvider struct {
	*IdentityProvider

	// non-standard oidc fields
	RevokeURL *url.URL
}

const defaultOneLoginProviderURL = "https://openid-connect.onelogin.com/oidc"

// NewOneLoginProvider creates a new instance of an OpenID Connect provider.
func NewOneLoginProvider(p *IdentityProvider) (*OneLoginProvider, error) {
	ctx := context.Background()
	if p.ProviderURL == "" {
		p.ProviderURL = defaultOneLoginProviderURL
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
	OneLoginProvider := OneLoginProvider{IdentityProvider: p}

	OneLoginProvider.RevokeURL, err = url.Parse(claims.RevokeURL)
	if err != nil {
		return nil, err
	}
	return &OneLoginProvider, nil
}

// Revoke revokes the access token a given session state.
// https://developers.onelogin.com/openid-connect/api/revoke-session
func (p *OneLoginProvider) Revoke(token string) error {
	params := url.Values{}
	params.Add("client_id", p.ClientID)
	params.Add("client_secret", p.ClientSecret)
	params.Add("token", token)
	params.Add("token_type_hint", "access_token")
	err := httputil.Client("POST", p.RevokeURL.String(), version.UserAgent(), params, nil)
	if err != nil && err != httputil.ErrTokenRevoked {
		log.Error().Err(err).Msg("authenticate/providers: failed to revoke session")
		return err
	}
	return nil
}

// GetSignInURL returns the sign in url with typical oauth parameters
func (p *OneLoginProvider) GetSignInURL(state string) string {
	return p.oauth.AuthCodeURL(state, oauth2.AccessTypeOffline)
}
