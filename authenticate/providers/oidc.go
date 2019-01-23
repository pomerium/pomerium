package providers // import "github.com/pomerium/pomerium/internal/providers"

import (
	"context"
	"errors"

	oidc "github.com/pomerium/go-oidc"
	"golang.org/x/oauth2"
)

// OIDCProvider provides a standard, OpenID Connect implementation
// of an authorization identity provider.
// see : https://openid.net/specs/openid-connect-core-1_0.html
type OIDCProvider struct {
	*ProviderData
}

// NewOIDCProvider creates a new instance of an OpenID Connect provider.
func NewOIDCProvider(p *ProviderData) (*OIDCProvider, error) {
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
	return &OIDCProvider{ProviderData: p}, nil
}
