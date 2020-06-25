// Package google implements OpenID Connect for Google and GSuite.
//
// https://www.pomerium.io/docs/identity-providers/google.html
// https://developers.google.com/identity/protocols/oauth2/openid-connect
package google

import (
	"context"
	"fmt"

	oidc "github.com/coreos/go-oidc"

	"github.com/pomerium/pomerium/internal/identity/oauth"
	pom_oidc "github.com/pomerium/pomerium/internal/identity/oidc"
)

const (
	// Name identifies the Google identity provider
	Name = "google"

	defaultProviderURL = "https://accounts.google.com"
)

var defaultScopes = []string{oidc.ScopeOpenID, "profile", "email"}

// https://developers.google.com/identity/protocols/oauth2/openid-connect#authenticationuriparameters
var defaultAuthCodeOptions = map[string]string{"prompt": "select_account consent"}

// Provider is a Google implementation of the Authenticator interface.
type Provider struct {
	*pom_oidc.Provider
}

// New instantiates an OpenID Connect (OIDC) session with Google.
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

	p.AuthCodeOptions = defaultAuthCodeOptions
	if len(o.AuthCodeOptions) != 0 {
		p.AuthCodeOptions = o.AuthCodeOptions
	}
	return &p, nil
}
