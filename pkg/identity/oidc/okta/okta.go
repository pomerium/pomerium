// Package okta implements OpenID Connect for okta
//
// https://www.pomerium.com/docs/identity-providers/okta
package okta

import (
	"context"
	"fmt"
	"maps"

	"github.com/pomerium/pomerium/pkg/identity/oauth"
	pom_oidc "github.com/pomerium/pomerium/pkg/identity/oidc"
)

const (
	// Name identifies the Okta identity provider
	Name = "okta"
)

// Provider is an Okta implementation of the Authenticator interface.
type Provider struct {
	*pom_oidc.Provider
}

// New instantiates an OpenID Connect (OIDC) provider for Okta.
func New(ctx context.Context, o *oauth.Options) (*Provider, error) {
	options := *o

	options.AuthCodeOptions = map[string]string{}
	maps.Copy(options.AuthCodeOptions, map[string]string{
		"client_secret": o.ClientSecret,
	})
	maps.Copy(options.AuthCodeOptions, o.AuthCodeOptions)

	var p Provider
	var err error
	genericOidc, err := pom_oidc.New(ctx, &options)
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
