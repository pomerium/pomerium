package providers // import "github.com/pomerium/pomerium/internal/providers"

import (
	"context"
	"errors"

	oidc "github.com/pomerium/go-oidc"
	"golang.org/x/oauth2"
)

// OIDCProvider provides a standard, OpenID Connect implementation
// of an authorization identity provider.
type OIDCProvider struct {
	*ProviderData
}

// NewOIDCProvider creates a new instance of an OpenID Connect provider.
func NewOIDCProvider(p *ProviderData) (*OIDCProvider, error) {
	ctx := context.Background()
	if p.ProviderURL == "" {
		return nil, errors.New("missing required provider url")
	}
	provider, err := oidc.NewProvider(ctx, p.ProviderURL)
	if err != nil {
		return nil, err
	}
	p.verifier = provider.Verifier(&oidc.Config{ClientID: p.ClientID})
	p.oauth = &oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: p.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  p.RedirectURL.String(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}
	return &OIDCProvider{ProviderData: p}, nil
}
