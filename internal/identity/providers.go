// Package identity provides support for making OpenID Connect (OIDC)
// and OAuth2 authenticated HTTP requests with third party identity providers.
package identity

import (
	"context"
	"fmt"
	"net/http"

	"golang.org/x/oauth2"

	"github.com/pomerium/pomerium/internal/identity/identity"
	"github.com/pomerium/pomerium/internal/identity/oauth"
	"github.com/pomerium/pomerium/internal/identity/oauth/apple"
	"github.com/pomerium/pomerium/internal/identity/oauth/github"
	"github.com/pomerium/pomerium/internal/identity/oidc"
	"github.com/pomerium/pomerium/internal/identity/oidc/auth0"
	"github.com/pomerium/pomerium/internal/identity/oidc/azure"
	"github.com/pomerium/pomerium/internal/identity/oidc/cognito"
	"github.com/pomerium/pomerium/internal/identity/oidc/gitlab"
	"github.com/pomerium/pomerium/internal/identity/oidc/google"
	"github.com/pomerium/pomerium/internal/identity/oidc/okta"
	"github.com/pomerium/pomerium/internal/identity/oidc/onelogin"
	"github.com/pomerium/pomerium/internal/identity/oidc/ping"
)

// Authenticator is an interface representing the ability to authenticate with an identity provider.
type Authenticator interface {
	Authenticate(context.Context, string, identity.State) (*oauth2.Token, error)
	Refresh(context.Context, *oauth2.Token, identity.State) (*oauth2.Token, error)
	Revoke(context.Context, *oauth2.Token) error
	Name() string
	UpdateUserInfo(ctx context.Context, t *oauth2.Token, v interface{}) error

	SignIn(w http.ResponseWriter, r *http.Request, state string) error
	SignOut(w http.ResponseWriter, r *http.Request, idTokenHint, authenticateSignedOutURL, redirectToURL string) error
}

// NewAuthenticator returns a new identity provider based on its name.
func NewAuthenticator(o oauth.Options) (a Authenticator, err error) {
	ctx := context.Background()
	switch o.ProviderName {
	case apple.Name:
		a, err = apple.New(ctx, &o)
	case auth0.Name:
		a, err = auth0.New(ctx, &o)
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
	case ping.Name:
		a, err = ping.New(ctx, &o)
	case cognito.Name:
		a, err = cognito.New(ctx, &o)
	case "":
		return nil, fmt.Errorf("identity: provider is not defined")
	default:
		return nil, fmt.Errorf("identity: unknown provider: %s", o.ProviderName)
	}
	if err != nil {
		return nil, err
	}
	return a, nil
}
