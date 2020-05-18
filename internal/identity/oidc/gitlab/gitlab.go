// Package gitlab implements OpenID Connect for Gitlab
//
// https://www.pomerium.io/docs/identity-providers/gitlab.html
package gitlab

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/coreos/go-oidc"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/identity/oauth"
	pom_oidc "github.com/pomerium/pomerium/internal/identity/oidc"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/version"
	"golang.org/x/oauth2"
)

// Name identifies the GitLab identity provider.
const Name = "gitlab"

var defaultScopes = []string{oidc.ScopeOpenID, "profile", "email", "api"}

const (
	defaultProviderURL = "https://gitlab.com"

	// groupPath is the url to return a list of groups for the authenticated user
	// https://docs.gitlab.com/ee/api/groups.html
	groupPath = "/api/v4/groups"
)

// Provider is a Gitlab implementation of the Authenticator interface.
type Provider struct {
	*pom_oidc.Provider

	userGroupURL string
}

// New instantiates an OpenID Connect (OIDC) provider for Gitlab.
func New(ctx context.Context, o *oauth.Options) (*Provider, error) {
	var p Provider
	var err error
	if o.ProviderURL == "" {
		o.ProviderURL = defaultProviderURL
	}
	if len(o.Scopes) == 0 {
		o.Scopes = defaultScopes
	}
	genericOidc, err := pom_oidc.New(ctx, o)
	if err != nil {
		return nil, fmt.Errorf("%s: failed creating oidc provider: %w", Name, err)
	}
	p.Provider = genericOidc
	p.UserGroupFn = p.UserGroups
	p.userGroupURL = o.ProviderURL + groupPath

	return &p, nil
}

// UserGroups returns a slice of groups for the user.
//
// Returns 20 results at a time because the API results are paginated.
// https://docs.gitlab.com/ee/api/groups.html#list-groups
func (p *Provider) UserGroups(ctx context.Context, t *oauth2.Token, v interface{}) error {
	var response []struct {
		ID                             json.Number `json:"id"`
		Name                           string      `json:"name,omitempty"`
		Path                           string      `json:"path,omitempty"`
		Description                    string      `json:"description,omitempty"`
		Visibility                     string      `json:"visibility,omitempty"`
		ShareWithGroupLock             bool        `json:"share_with_group_lock,omitempty"`
		RequireTwoFactorAuthentication bool        `json:"require_two_factor_authentication,omitempty"`
		SubgroupCreationLevel          string      `json:"subgroup_creation_level,omitempty"`
		FullName                       string      `json:"full_name,omitempty"`
		FullPath                       string      `json:"full_path,omitempty"`
	}
	headers := map[string]string{"Authorization": fmt.Sprintf("Bearer %s", t.AccessToken)}
	err := httputil.Client(ctx, http.MethodGet, p.userGroupURL, version.UserAgent(), headers, nil, &response)
	if err != nil {
		return err
	}
	log.Debug().Interface("response", response).Msg("gitlab: groups")
	var out struct {
		Groups []string `json:"groups"`
	}
	for _, group := range response {
		out.Groups = append(out.Groups, group.ID.String())
	}
	b, err := json.Marshal(out)
	if err != nil {
		return err
	}

	return json.Unmarshal(b, v)
}
