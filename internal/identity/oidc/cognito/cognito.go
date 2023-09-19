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

// Name identifies the Cognito identity provider
const Name = "cognito"

// Provider is an Cognito implementation of the Authenticator interface.
type Provider struct {
	*pom_oidc.Provider
}

// New instantiates an OpenID Connect (OIDC) provider for AWS Cognito.
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

	return &p, nil
}

// GetSignOutURL gets the sign out URL according to https://docs.aws.amazon.com/cognito/latest/developerguide/logout-endpoint.html.
func (p *Provider) GetSignOutURL(idTokenHint, returnToURL string) (string, error) {
	oa, err := p.GetOauthConfig()
	if err != nil {
		return "", fmt.Errorf("error getting cognito oauth config: %w", err)
	}

	authURL, err := urlutil.ParseAndValidateURL(oa.Endpoint.AuthURL)
	if err != nil {
		return "", fmt.Errorf("error getting cognito endpoint auth url: %w", err)
	}

	logOutQuery := url.Values{
		"client_id": []string{oa.ClientID},
	}
	if returnToURL != "" {
		logOutQuery.Set("logout_uri", returnToURL)
	}
	logOutURL := authURL.ResolveReference(&url.URL{
		Path:     "/logout",
		RawQuery: logOutQuery.Encode(),
	})
	return logOutURL.String(), nil
}
