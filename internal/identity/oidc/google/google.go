// Package google implements OpenID Connect for Google and GSuite.
//
// https://www.pomerium.io/docs/identity-providers/google.html
// https://developers.google.com/identity/protocols/oauth2/openid-connect
package google

import (
	"context"
	"fmt"

	oidc "github.com/coreos/go-oidc"
	"golang.org/x/oauth2"

	"github.com/pomerium/pomerium/internal/identity/oauth"
	pom_oidc "github.com/pomerium/pomerium/internal/identity/oidc"
)

const (
	// Name identifies the Google identity provider
	Name = "google"

	defaultProviderURL = "https://accounts.google.com"
)

var defaultScopes = []string{oidc.ScopeOpenID, "profile", "email"}

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

	return &p, nil
}

// GetSignInURL returns a URL to OAuth 2.0 provider's consent page that asks for permissions for
// the required scopes explicitly.
// Google requires an additional access scope for offline access which is a requirement for any
// application that needs to access a Google API when the user is not present.
// Support for this scope differs between OpenID Connect providers. For instance
// Google rejects it, favoring appending "access_type=offline" as part of the
// authorization request instead.
// Google only provide refresh_token on the first authorization from the user. If user clears
// cookies, re-authorization will not bring back refresh_token. A work around to this is to add
// prompt=consent to the OAuth redirect URL and will always return a refresh_token.
// https://openid.net/specs/openid-connect-core-1_0.html#OfflineAccess
func (p *Provider) GetSignInURL(state string) string {
	return p.Oauth.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.SetAuthURLParam("prompt", "select_account consent"))
}
