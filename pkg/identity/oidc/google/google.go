// Package google implements OpenID Connect for Google and GSuite.
//
// https://www.pomerium.com/docs/identity-providers/google
// https://developers.google.com/identity/protocols/oauth2/openid-connect
package google

import (
	"context"
	"fmt"

	oidc "github.com/coreos/go-oidc/v3/oidc"

	"github.com/pomerium/pomerium/pkg/identity/oauth"
	pom_oidc "github.com/pomerium/pomerium/pkg/identity/oidc"
)

const (
	// Name identifies the Google identity provider
	Name = "google"

	defaultProviderURL = "https://accounts.google.com"
)

var defaultScopes = []string{oidc.ScopeOpenID, "profile", "email"}

// unlike other identity providers, google does not support the `offline_access` scope and instead
// requires we set this on a custom uri param. Also, ` prompt` must be set to `consent`to ensure
// that our application always receives a refresh token (ask google). And finally, we default to
// having the user select which Google account they'd like to use.
// For more details, please see google's documentation:
//
//	https://developers.google.com/identity/protocols/oauth2/web-server#offline
//	https://developers.google.com/identity/protocols/oauth2/openid-connect#authenticationuriparameters
var defaultAuthCodeOptions = map[string]string{"prompt": "select_account consent", "access_type": "offline"}

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
	if o.AuthCodeOptions != nil {
		p.AuthCodeOptions = o.AuthCodeOptions
	}
	return &p, nil
}

// Name returns the provider name.
func (p *Provider) Name() string {
	return Name
}
