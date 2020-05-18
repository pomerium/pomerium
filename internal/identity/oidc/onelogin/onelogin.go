// Package onelogin implements OpenID Connect for OneLogin
//
// https://www.pomerium.io/docs/identity-providers/one-login.html
package onelogin

import (
	"context"
	"fmt"
	"net/http"

	oidc "github.com/coreos/go-oidc"
	"golang.org/x/oauth2"

	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/identity/oauth"
	pom_oidc "github.com/pomerium/pomerium/internal/identity/oidc"
	"github.com/pomerium/pomerium/internal/version"
)

const (
	// Name identifies the OneLogin identity provider
	Name = "onelogin"

	defaultProviderURL      = "https://openid-connect.onelogin.com/oidc"
	defaultOneloginGroupURL = "https://openid-connect.onelogin.com/oidc/me"
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
	p.UserGroupFn = p.UserGroups
	return &p, nil
}

// UserGroups returns a slice of group names a given user is in.
// https://developers.onelogin.com/openid-connect/api/user-info
func (p *Provider) UserGroups(ctx context.Context, t *oauth2.Token, v interface{}) error {
	if t == nil {
		return pom_oidc.ErrMissingAccessToken
	}
	headers := map[string]string{"Authorization": fmt.Sprintf("Bearer %s", t.AccessToken)}
	return httputil.Client(ctx, http.MethodGet, defaultOneloginGroupURL, version.UserAgent(), headers, nil, v)
}
