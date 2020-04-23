// Package identity provides support for making OpenID Connect (OIDC)
// and OAuth2 authenticated HTTP requests with third party identity providers.
package identity

import (
	"context"
	"fmt"
	"net/url"

	"golang.org/x/oauth2"

	"github.com/pomerium/pomerium/internal/identity/oauth"
	"github.com/pomerium/pomerium/internal/identity/oauth/github"
	"github.com/pomerium/pomerium/internal/identity/oidc"
	"github.com/pomerium/pomerium/internal/identity/oidc/azure"
	"github.com/pomerium/pomerium/internal/identity/oidc/gitlab"
	"github.com/pomerium/pomerium/internal/identity/oidc/google"
	"github.com/pomerium/pomerium/internal/identity/oidc/okta"
	"github.com/pomerium/pomerium/internal/identity/oidc/onelogin"
	"github.com/pomerium/pomerium/internal/sessions"
)

var (
	// compile time assertions that providers are satisfying the interface
	_ Authenticator = &azure.Provider{}
	_ Authenticator = &gitlab.Provider{}
	_ Authenticator = &github.Provider{}
	_ Authenticator = &google.Provider{}
	_ Authenticator = &oidc.Provider{}
	_ Authenticator = &okta.Provider{}
	_ Authenticator = &onelogin.Provider{}
	_ Authenticator = &MockProvider{}
)

// Authenticator is an interface representing the ability to authenticate with an identity provider.
type Authenticator interface {
	Authenticate(context.Context, string) (*sessions.State, error)
	Refresh(context.Context, *sessions.State) (*sessions.State, error)
	Revoke(context.Context, *oauth2.Token) error
	GetSignInURL(state string) string
	LogOut() (*url.URL, error)
}

// NewAuthenticator returns a new identity provider based on its name.
func NewAuthenticator(o oauth.Options) (a Authenticator, err error) {
	ctx := context.Background()
	switch o.ProviderName {
	case azure.Name:
		a, err = azure.New(ctx, &o)
	case gitlab.Name:
		a, err = gitlab.New(ctx, &o)
	case github.Name:
		a, err = github.New(ctx, &o)
	case google.Name:
		a, err = google.New(ctx, &o)
	case oidc.Name:
		a, err = oidc.New(ctx, &o)
	case okta.Name:
		a, err = okta.New(ctx, &o)
	case onelogin.Name:
		a, err = onelogin.New(ctx, &o)
	default:
		return nil, fmt.Errorf("identity: unknown provider: %s", o.ProviderName)
	}
	if err != nil {
		return nil, err
	}
	return a, nil
}
