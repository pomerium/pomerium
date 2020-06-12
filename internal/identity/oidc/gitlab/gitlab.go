// Package gitlab implements OpenID Connect for Gitlab
//
// https://www.pomerium.io/docs/identity-providers/gitlab.html
package gitlab

import (
	"context"
	"fmt"

	"github.com/coreos/go-oidc"

	"github.com/pomerium/pomerium/internal/identity/oauth"
	pom_oidc "github.com/pomerium/pomerium/internal/identity/oidc"
)

// Name identifies the GitLab identity provider.
const Name = "gitlab"

var defaultScopes = []string{oidc.ScopeOpenID, "profile", "email", "api"}

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
