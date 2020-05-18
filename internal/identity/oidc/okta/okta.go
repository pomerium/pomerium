// Package okta implements OpenID Connect for okta
//
// https://www.pomerium.io/docs/identity-providers/okta.html
package okta

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/identity/oauth"
	pom_oidc "github.com/pomerium/pomerium/internal/identity/oidc"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/internal/version"
	"golang.org/x/oauth2"
)

const (
	// Name identifies the Okta identity provider
	Name = "okta"

	// https://developer.okta.com/docs/reference/api/users/
	userAPIPath = "/api/v1/users/"
)

// Provider is an Okta implementation of the Authenticator interface.
type Provider struct {
	*pom_oidc.Provider

	userAPI *url.URL

	// serviceAccount is the the custom HTTP authentication used for okta
	// https://developer.okta.com/docs/reference/api-overview/#authentication
	serviceAccount string
}

// New instantiates an OpenID Connect (OIDC) provider for Okta.
func New(ctx context.Context, o *oauth.Options) (*Provider, error) {
	var p Provider
	var err error
	genericOidc, err := pom_oidc.New(ctx, o)
	if err != nil {
		return nil, fmt.Errorf("%s: failed creating oidc provider: %w", Name, err)
	}
	p.Provider = genericOidc

	if o.ServiceAccount != "" {
		userAPI, err := urlutil.ParseAndValidateURL(o.ProviderURL)
		if err != nil {
			return nil, err
		}
		p.userAPI = userAPI
		p.userAPI.Path = userAPIPath
		p.serviceAccount = o.ServiceAccount
		p.UserGroupFn = p.UserGroups
	} else {
		log.Warn().Msg("okta: api token not set, cannot retrieve groups")
	}
	return &p, nil
}

// UserGroups fetches the groups of which the user is a member
// https://developer.okta.com/docs/reference/api/users/#get-user-s-groups
func (p *Provider) UserGroups(ctx context.Context, t *oauth2.Token, v interface{}) error {
	s, err := p.GetSubject(v)
	if err != nil {
		return err
	}
	var response []struct {
		ID      string `json:"id"`
		Profile struct {
			Name        string `json:"name"`
			Description string `json:"description"`
		} `json:"profile"`
	}

	headers := map[string]string{"Authorization": fmt.Sprintf("SSWS %s", p.serviceAccount)}
	uri := fmt.Sprintf("%s/%s/groups", p.userAPI.String(), s)
	err = httputil.Client(ctx, http.MethodGet, uri, version.UserAgent(), headers, nil, &response)
	if err != nil {
		return err
	}
	log.Debug().Interface("response", response).Msg("okta: groups")
	var out struct {
		Groups []string `json:"groups"`
	}
	for _, group := range response {
		out.Groups = append(out.Groups, group.ID)
	}
	b, err := json.Marshal(out)
	if err != nil {
		return err
	}

	return json.Unmarshal(b, v)
}
