// Package gitlab implements OpenID Connect for Gitlab
//
// https://www.pomerium.com/docs/identity-providers/gitlab
package gitlab

import (
	"context"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/pomerium/pomerium/pkg/identity/oauth"
	pom_oidc "github.com/pomerium/pomerium/pkg/identity/oidc"
)

// Name identifies the GitLab identity provider.
const Name = "gitlab"

var defaultScopes = []string{oidc.ScopeOpenID, "profile", "email"}

const (
	defaultProviderURL = "https://gitlab.com"
)

// Provider is a Gitlab implementation of the Authenticator interface.
type Provider struct {
	*pom_oidc.Provider
}

// New instantiates an OpenID Connect (OIDC) provider for Gitlab.
func New(ctx context.Context, o *oauth.Options) (*Provider, error) {
	var p Provider
	var err error
	if o.ProviderURL == "" {
		o.ProviderURL = defaultProviderURL
	}
	if len(o.Scopes) == 0 {
		o.Scopes = defaultScopes
	}
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
