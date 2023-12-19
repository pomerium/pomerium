// Package cognito provides support for AWS Cognito
package cognito

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/pomerium/pomerium/internal/httputil"
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

// SignOut implements sign out according to https://docs.aws.amazon.com/cognito/latest/developerguide/logout-endpoint.html.
func (p *Provider) SignOut(w http.ResponseWriter, r *http.Request, _, authenticateSignedOutURL, returnToURL string) error {
	oa, err := p.GetOauthConfig()
	if err != nil {
		return fmt.Errorf("error getting cognito oauth config: %w", err)
	}

	authURL, err := urlutil.ParseAndValidateURL(oa.Endpoint.AuthURL)
	if err != nil {
		return fmt.Errorf("error getting cognito endpoint auth url: %w", err)
	}

	logOutQuery := url.Values{
		"client_id": []string{oa.ClientID},
	}
	if authenticateSignedOutURL != "" {
		logOutQuery.Set("logout_uri", authenticateSignedOutURL)
	}
	if returnToURL != "" {
		httputil.SetSignedOutRedirectURICookie(w, returnToURL)
	}
	logOutURL := authURL.ResolveReference(&url.URL{
		Path:     "/logout",
		RawQuery: logOutQuery.Encode(),
	})
	httputil.Redirect(w, r, logOutURL.String(), http.StatusFound)
	return nil
}
