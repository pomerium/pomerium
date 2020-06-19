// Package onelogin implements OpenID Connect for OneLogin
//
// https://www.pomerium.io/docs/identity-providers/one-login.html
package onelogin

import (
	"context"
	"fmt"

	oidc "github.com/coreos/go-oidc"

	"github.com/pomerium/pomerium/internal/identity/oauth"
	pom_oidc "github.com/pomerium/pomerium/internal/identity/oidc"
)

const (
	// Name identifies the OneLogin identity provider
	Name = "onelogin"

	defaultProviderURL = "https://openid-connect.onelogin.com/oidc"
)

var defaultScopes = []string{oidc.ScopeOpenID, "profile", "email", "groups", "offline_access"}

// Provider is an OneLogin implementation of the Authenticator interface.
type Provider struct {
	*pom_oidc.Provider
}

// New instantiates an OpenID Connect (OIDC) provider for OneLogin.
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
