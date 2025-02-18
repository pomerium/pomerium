// Package identity provides support for making OpenID Connect (OIDC)
// and OAuth2 authenticated HTTP requests with third party identity providers.
package identity

import (
	"context"
	"fmt"
	"net/http"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"golang.org/x/oauth2"

	"github.com/pomerium/pomerium/pkg/identity/identity"
	"github.com/pomerium/pomerium/pkg/identity/oauth"
	"github.com/pomerium/pomerium/pkg/identity/oauth/apple"
	"github.com/pomerium/pomerium/pkg/identity/oauth/github"
	"github.com/pomerium/pomerium/pkg/identity/oidc"
	"github.com/pomerium/pomerium/pkg/identity/oidc/auth0"
	"github.com/pomerium/pomerium/pkg/identity/oidc/azure"
	"github.com/pomerium/pomerium/pkg/identity/oidc/cognito"
	"github.com/pomerium/pomerium/pkg/identity/oidc/gitlab"
	"github.com/pomerium/pomerium/pkg/identity/oidc/google"
	"github.com/pomerium/pomerium/pkg/identity/oidc/okta"
	"github.com/pomerium/pomerium/pkg/identity/oidc/onelogin"
	"github.com/pomerium/pomerium/pkg/identity/oidc/ping"
	oteltrace "go.opentelemetry.io/otel/trace"
)

// State is the identity state.
type State = identity.State

// Authenticator is an interface representing the ability to authenticate with an identity provider.
type Authenticator interface {
	Authenticate(context.Context, string, State) (*oauth2.Token, error)
	Refresh(context.Context, *oauth2.Token, State) (*oauth2.Token, error)
	Revoke(context.Context, *oauth2.Token) error
	Name() string
	UpdateUserInfo(ctx context.Context, t *oauth2.Token, v any) error

	SignIn(w http.ResponseWriter, r *http.Request, state string) error
	SignOut(w http.ResponseWriter, r *http.Request, idTokenHint, authenticateSignedOutURL, redirectToURL string) error

	// alternatives for these methods?
	DeviceAuth(ctx context.Context) (*oauth2.DeviceAuthResponse, error)
	DeviceAccessToken(ctx context.Context, r *oauth2.DeviceAuthResponse, state State) (*oauth2.Token, error)
}

// AuthenticatorConstructor makes an Authenticator from the given options.
type AuthenticatorConstructor func(context.Context, *oauth.Options) (Authenticator, error)

var registry = map[string]AuthenticatorConstructor{}

// RegisterAuthenticator registers a new Authenticator.
func RegisterAuthenticator(name string, ctor AuthenticatorConstructor) {
	registry[name] = ctor
}

func init() {
	RegisterAuthenticator(apple.Name, func(ctx context.Context, o *oauth.Options) (Authenticator, error) { return apple.New(ctx, o) })
	RegisterAuthenticator(auth0.Name, func(ctx context.Context, o *oauth.Options) (Authenticator, error) { return auth0.New(ctx, o) })
	RegisterAuthenticator(azure.Name, func(ctx context.Context, o *oauth.Options) (Authenticator, error) { return azure.New(ctx, o) })
	RegisterAuthenticator(cognito.Name, func(ctx context.Context, o *oauth.Options) (Authenticator, error) { return cognito.New(ctx, o) })
	RegisterAuthenticator(github.Name, func(ctx context.Context, o *oauth.Options) (Authenticator, error) { return github.New(ctx, o) })
	RegisterAuthenticator(gitlab.Name, func(ctx context.Context, o *oauth.Options) (Authenticator, error) { return gitlab.New(ctx, o) })
	RegisterAuthenticator(google.Name, func(ctx context.Context, o *oauth.Options) (Authenticator, error) { return google.New(ctx, o) })
	RegisterAuthenticator(oidc.Name, func(ctx context.Context, o *oauth.Options) (Authenticator, error) { return oidc.New(ctx, o) })
	RegisterAuthenticator(okta.Name, func(ctx context.Context, o *oauth.Options) (Authenticator, error) { return okta.New(ctx, o) })
	RegisterAuthenticator(onelogin.Name, func(ctx context.Context, o *oauth.Options) (Authenticator, error) { return onelogin.New(ctx, o) })
	RegisterAuthenticator(ping.Name, func(ctx context.Context, o *oauth.Options) (Authenticator, error) { return ping.New(ctx, o) })
}

// NewAuthenticator returns a new identity provider based on its name.
func NewAuthenticator(ctx context.Context, tracerProvider oteltrace.TracerProvider, o oauth.Options) (a Authenticator, err error) {
	if o.ProviderName == "" {
		return nil, fmt.Errorf("identity: provider is not defined")
	}

	ctx = context.WithValue(ctx, oauth2.HTTPClient, &http.Client{
		Transport: otelhttp.NewTransport(nil,
			otelhttp.WithTracerProvider(tracerProvider),
			otelhttp.WithSpanNameFormatter(func(_ string, r *http.Request) string {
				return fmt.Sprintf("OAuth2 Client: %s %s", r.Method, r.URL.Path)
			}),
		),
	})

	ctor, ok := registry[o.ProviderName]
	if !ok {
		return nil, fmt.Errorf("identity: unknown provider: %s", o.ProviderName)
	}

	return ctor(ctx, &o)
}
