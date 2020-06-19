// Package azure implements OpenID Connect for Microsoft Azure
//
// https://www.pomerium.io/docs/identity-providers/azure.html
package azure

import (
	"context"
	"fmt"

	"golang.org/x/oauth2"

	"github.com/pomerium/pomerium/internal/identity/oauth"
	pom_oidc "github.com/pomerium/pomerium/internal/identity/oidc"
)

// Name identifies the Azure identity provider
const Name = "azure"

// defaultProviderURL Users with both a personal Microsoft
// account and a work or school account from Azure Active Directory (Azure AD)
// an sign in to the application.
const defaultProviderURL = "https://login.microsoftonline.com/common"

// Provider is an Azure implementation of the Authenticator interface.
type Provider struct {
	*pom_oidc.Provider
}

// New instantiates an OpenID Connect (OIDC) provider for Azure.
func New(ctx context.Context, o *oauth.Options) (*Provider, error) {
	var p Provider
	var err error
	if o.ProviderURL == "" {
		o.ProviderURL = defaultProviderURL
	}
	genericOidc, err := pom_oidc.New(ctx, o)
	if err != nil {
		return nil, fmt.Errorf("%s: failed creating oidc provider: %w", Name, err)
	}
	p.Provider = genericOidc
	return &p, nil
}

// GetSignInURL returns the sign in url with typical oauth parameters
// https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-implicit-grant-flow
func (p *Provider) GetSignInURL(state string) string {
	return p.Oauth.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.SetAuthURLParam("prompt", "select_account"))
}
