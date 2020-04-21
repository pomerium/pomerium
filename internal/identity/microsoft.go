package identity

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	oidc "github.com/coreos/go-oidc"
	"golang.org/x/oauth2"

	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/version"
)

// defaultAzureProviderURL Users with both a personal Microsoft
// account and a work or school account from Azure Active Directory (Azure AD)
// an sign in to the application.
const defaultAzureProviderURL = "https://login.microsoftonline.com/common"
const defaultAzureGroupURL = "https://graph.microsoft.com/v1.0/me/memberOf"

// AzureProvider is an implementation of the Provider interface
type AzureProvider struct {
	*Provider
}

// NewAzureProvider returns a new AzureProvider and sets the provider url endpoints.
// https://www.pomerium.io/docs/identity-providers.html#azure-active-directory
func NewAzureProvider(p *Provider) (*AzureProvider, error) {
	ctx := context.Background()
	if p.ProviderURL == "" {
		p.ProviderURL = defaultAzureProviderURL
	}
	var err error
	p.provider, err = oidc.NewProvider(ctx, p.ProviderURL)
	if err != nil {
		return nil, err
	}
	if len(p.Scopes) == 0 {
		p.Scopes = []string{oidc.ScopeOpenID, "profile", "email", "offline_access", "Group.Read.All"}
	}
	p.verifier = p.provider.Verifier(&oidc.Config{ClientID: p.ClientID})
	p.oauth = &oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: p.ClientSecret,
		Endpoint:     p.provider.Endpoint(),
		RedirectURL:  p.RedirectURL.String(),
		Scopes:       p.Scopes,
	}

	azureProvider := &AzureProvider{Provider: p}
	if err := p.provider.Claims(&azureProvider); err != nil {
		return nil, err
	}

	p.UserGroupFn = azureProvider.UserGroups

	return azureProvider, nil
}

// GetSignInURL returns the sign in url with typical oauth parameters
func (p *AzureProvider) GetSignInURL(state string) string {
	return p.oauth.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.SetAuthURLParam("prompt", "select_account"))
}

// UserGroups returns a slice of group names a given user is in.
// `Directory.Read.All` is required.
// https://docs.microsoft.com/en-us/graph/api/resources/directoryobject?view=graph-rest-1.0
// https://docs.microsoft.com/en-us/graph/api/user-list-memberof?view=graph-rest-1.0
func (p *AzureProvider) UserGroups(ctx context.Context, s *sessions.State) ([]string, error) {
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
	err := httputil.Client(ctx, http.MethodGet, defaultAzureGroupURL, version.UserAgent(), headers, nil, &response)
	if err != nil {
		return nil, err
	}
	var groups []string
	for _, group := range response.Groups {
		log.Debug().Str("DisplayName", group.DisplayName).Str("ID", group.ID).Msg("identity/microsoft: group")
		groups = append(groups, group.ID)
	}
	return groups, nil
}
