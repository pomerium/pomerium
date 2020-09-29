// Package auth0 implements OpenID Connect for auth0
//
// https://www.pomerium.io/docs/identity-providers/auth0.html
package auth0

import (
	"context"
	"fmt"
	"strings"

	"github.com/pomerium/pomerium/internal/identity/oauth"
	pom_oidc "github.com/pomerium/pomerium/internal/identity/oidc"
)

const (
	// Name identifies the Auth0 identity provider
	Name = "auth0"
)

// Provider is an Auth0 implementation of the Authenticator interface.
type Provider struct {
	*pom_oidc.Provider
}

// New instantiates an OpenID Connect (OIDC) provider for Auth0.
func New(ctx context.Context, o *oauth.Options) (*Provider, error) {
	// allow URLs that don't have a trailing slash
	if !strings.HasSuffix(o.ProviderURL, "/") {
		tmp := new(oauth.Options)
		*tmp = *o
		tmp.ProviderURL += "/"
		o = tmp
	}

	var p Provider
	var err error
	genericOidc, err := pom_oidc.New(ctx, o)
	if err != nil {
		return nil, fmt.Errorf("%s: failed creating oidc provider: %w", Name, err)
	}
	p.Provider = genericOidc

	return &p, nil
}

// Name returns the provider name.
func (p *Provider) Name() string {
	return Name
}
