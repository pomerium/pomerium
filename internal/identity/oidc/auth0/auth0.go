// Package auth0 implements OpenID Connect for auth0
//
// https://www.pomerium.com/docs/identity-providers/auth0
package auth0

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/pomerium/pomerium/internal/identity/oauth"
	pom_oidc "github.com/pomerium/pomerium/internal/identity/oidc"
	"github.com/pomerium/pomerium/internal/urlutil"
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

// GetSignOutURL implements logout as described in https://auth0.com/docs/api/authentication#logout.
func (p *Provider) GetSignOutURL(_, redirectToURL string) (string, error) {
	oa, err := p.GetOauthConfig()
	if err != nil {
		return "", fmt.Errorf("error getting auth0 oauth config: %w", err)
	}

	authURL, err := urlutil.ParseAndValidateURL(oa.Endpoint.AuthURL)
	if err != nil {
		return "", fmt.Errorf("error parsing auth0 endpoint auth url: %w", err)
	}

	logoutQuery := url.Values{
		"client_id": {oa.ClientID},
	}
	if redirectToURL != "" {
		logoutQuery.Set("returnTo", redirectToURL)
	}
	logoutURL := authURL.ResolveReference(&url.URL{
		Path:     "/v2/logout",
		RawQuery: logoutQuery.Encode(),
	})
	return logoutURL.String(), nil
}
