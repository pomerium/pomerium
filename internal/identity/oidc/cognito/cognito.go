// Package cognito provides support for AWS Cognito
package cognito

import (
	"context"
	"fmt"
	"net/url"

	"github.com/pomerium/pomerium/internal/identity/oauth"
	pom_oidc "github.com/pomerium/pomerium/internal/identity/oidc"
	"github.com/pomerium/pomerium/internal/urlutil"
)

var defaultScopes = []string{"openid", "email", "profile"}

const (
	// Name identifies the Auth0 identity provider
	Name = "cognito"
)

// Provider is an Cognito implementation of the Authenticator interface.
type Provider struct {
	*pom_oidc.Provider
}

// New instantiates an OpenID Connect (OIDC) provider for Auth0.
func New(ctx context.Context, opts *oauth.Options) (*Provider, error) {
	var p Provider

	if opts.Scopes == nil {
		opts.Scopes = defaultScopes
	}

	genericOIDC, err := pom_oidc.New(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("failed creating oidc provider: %w", err)
	}
	p.Provider = genericOIDC

	cognitoProvider, err := genericOIDC.GetProvider()
	if err != nil {
		return nil, fmt.Errorf("failed getting cognito provider: %w", err)
	}

	cognitoURL, err := urlutil.ParseAndValidateURL(cognitoProvider.Endpoint().AuthURL)
	if err != nil {
		return nil, fmt.Errorf("cannot parse cognito auth url: %w", err)
	}

	// https://docs.aws.amazon.com/cognito/latest/developerguide/revocation-endpoint.html
	p.RevocationURL = cognitoURL.ResolveReference(&url.URL{Path: "/oauth2/revoke"}).String()

	// https://docs.aws.amazon.com/cognito/latest/developerguide/logout-endpoint.html
	p.EndSessionURL = cognitoURL.ResolveReference(&url.URL{
		Path: "/logout",
		RawQuery: url.Values{
			"client_id":  []string{opts.ClientID},
			"logout_uri": []string{opts.RedirectURL.ResolveReference(&url.URL{Path: "/"}).String()},
		}.Encode(),
	}).String()

	return &p, nil
}
