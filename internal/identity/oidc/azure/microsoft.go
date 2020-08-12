// Package azure implements OpenID Connect for Microsoft Azure
//
// https://www.pomerium.io/docs/identity-providers/azure.html
package azure

import (
	"context"
	"fmt"

	"github.com/pomerium/pomerium/internal/identity/oauth"
	pom_oidc "github.com/pomerium/pomerium/internal/identity/oidc"
)

// Name identifies the Azure identity provider
const Name = "azure"

// defaultProviderURL Users with both a personal Microsoft
// account and a work or school account from Azure Active Directory (Azure AD)
// an sign in to the application.
const defaultProviderURL = "https://login.microsoftonline.com/common"

// https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow#request-an-authorization-code
var defaultAuthCodeOptions = map[string]string{"prompt": "select_account"}

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

	p.AuthCodeOptions = defaultAuthCodeOptions
	if len(o.AuthCodeOptions) != 0 {
		p.AuthCodeOptions = o.AuthCodeOptions
	}

	return &p, nil
}

// Name returns the provider name.
func (p *Provider) Name() string {
	return Name
}
