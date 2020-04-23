// Package azure implements OpenID Connect for Microsoft Azure
//
// https://www.pomerium.io/docs/identity-providers/azure.html
package azure

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"golang.org/x/oauth2"

	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/identity/oauth"
	pom_oidc "github.com/pomerium/pomerium/internal/identity/oidc"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/version"
)

// Name identifies the Azure identity provider
const Name = "azure"

// defaultProviderURL Users with both a personal Microsoft
// account and a work or school account from Azure Active Directory (Azure AD)
// an sign in to the application.
const defaultProviderURL = "https://login.microsoftonline.com/common"
const defaultGroupURL = "https://graph.microsoft.com/v1.0/me/memberOf"

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
	p.UserGroupFn = p.UserGroups
	return &p, nil
}

// GetSignInURL returns the sign in url with typical oauth parameters
// https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-implicit-grant-flow
func (p *Provider) GetSignInURL(state string) string {
	return p.Oauth.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.SetAuthURLParam("prompt", "select_account"))
}

// UserGroups returns a slice of group names a given user is in.
// `Directory.Read.All` is required.
// https://docs.microsoft.com/en-us/graph/api/resources/directoryobject?view=graph-rest-1.0
// https://docs.microsoft.com/en-us/graph/api/user-list-memberof?view=graph-rest-1.0
func (p *Provider) UserGroups(ctx context.Context, s *sessions.State) ([]string, error) {
	if s == nil || s.AccessToken == nil {
		return nil, errors.New("identity/azure: session cannot be nil")
	}
	var response struct {
		Groups []struct {
			ID              string    `json:"id"`
			Description     string    `json:"description,omitempty"`
			DisplayName     string    `json:"displayName"`
			CreatedDateTime time.Time `json:"createdDateTime,omitempty"`
			GroupTypes      []string  `json:"groupTypes,omitempty"`
		} `json:"value"`
	}
	headers := map[string]string{"Authorization": fmt.Sprintf("Bearer %s", s.AccessToken.AccessToken)}
	err := httputil.Client(ctx, http.MethodGet, defaultGroupURL, version.UserAgent(), headers, nil, &response)
	if err != nil {
		return nil, err
	}
	var groups []string
	for _, group := range response.Groups {
		log.Debug().Str("DisplayName", group.DisplayName).Str("ID", group.ID).Msg("microsoft: group")
		groups = append(groups, group.ID)
	}
	return groups, nil
}
