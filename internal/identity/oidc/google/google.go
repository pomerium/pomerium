// Package google implements OpenID Connect for Google and GSuite.
//
// https://www.pomerium.io/docs/identity-providers/google.html
// https://developers.google.com/identity/protocols/oauth2/openid-connect
package google

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	oidc "github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	admin "google.golang.org/api/admin/directory/v1"

	"github.com/pomerium/pomerium/internal/identity/oauth"
	pom_oidc "github.com/pomerium/pomerium/internal/identity/oidc"
	"github.com/pomerium/pomerium/internal/log"
)

const (
	// Name identifies the Google identity provider
	Name = "google"

	defaultProviderURL = "https://accounts.google.com"
)

var defaultScopes = []string{oidc.ScopeOpenID, "profile", "email"}

// Provider is a Google implementation of the Authenticator interface.
type Provider struct {
	*pom_oidc.Provider

	// todo(bdd): we could probably save on a big ol set of imports
	// by calling this API directly
	apiClient *admin.Service
}

// New instantiates an OpenID Connect (OIDC) session with Google.
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
	if o.ServiceAccount == "" {
		log.Warn().Msg("google: no service account, will not fetch groups")
		return &p, nil
	}

	apiCreds, err := base64.StdEncoding.DecodeString(o.ServiceAccount)
	if err != nil {
		return nil, fmt.Errorf("google: could not decode service account json %w", err)
	}
	// Required scopes for groups api
	// https://developers.google.com/admin-sdk/directory/v1/reference/groups/list
	conf, err := google.JWTConfigFromJSON(apiCreds, admin.AdminDirectoryUserReadonlyScope, admin.AdminDirectoryGroupReadonlyScope)
	if err != nil {
		return nil, fmt.Errorf("google: failed making jwt config from json %w", err)
	}
	var credentialsFile struct {
		ImpersonateUser string `json:"impersonate_user"`
	}
	if err := json.Unmarshal(apiCreds, &credentialsFile); err != nil {
		return nil, err
	}
	conf.Subject = credentialsFile.ImpersonateUser
	client := conf.Client(context.TODO())
	p.apiClient, err = admin.New(client)
	if err != nil {
		return nil, fmt.Errorf("google: failed creating admin service %w", err)
	}
	p.UserGroupFn = p.UserGroups

	return &p, nil
}

// GetSignInURL returns a URL to OAuth 2.0 provider's consent page that asks for permissions for
// the required scopes explicitly.
// Google requires an additional access scope for offline access which is a requirement for any
// application that needs to access a Google API when the user is not present.
// Support for this scope differs between OpenID Connect providers. For instance
// Google rejects it, favoring appending "access_type=offline" as part of the
// authorization request instead.
// Google only provide refresh_token on the first authorization from the user. If user clears
// cookies, re-authorization will not bring back refresh_token. A work around to this is to add
// prompt=consent to the OAuth redirect URL and will always return a refresh_token.
// https://openid.net/specs/openid-connect-core-1_0.html#OfflineAccess
func (p *Provider) GetSignInURL(state string) string {
	return p.Oauth.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.SetAuthURLParam("prompt", "select_account consent"))
}

// UserGroups returns a slice of group names a given user is in
// NOTE: groups via Directory API is limited to 1 QPS!
// https://developers.google.com/admin-sdk/directory/v1/reference/groups/list
// https://developers.google.com/admin-sdk/directory/v1/limits
func (p *Provider) UserGroups(ctx context.Context, t *oauth2.Token, v interface{}) error {
	if p.apiClient == nil {
		return errors.New("google: trying to fetch groups, but no api client")
	}
	s, err := p.GetSubject(v)
	if err != nil {
		return err
	}
	var out struct {
		Groups []string `json:"groups"`
	}
	req := p.apiClient.Groups.List().Context(ctx).UserKey(s)
	err = req.Pages(ctx, func(resp *admin.Groups) error {
		for _, group := range resp.Groups {
			out.Groups = append(out.Groups, group.Email)
		}
		return nil
	})
	if err != nil {
		return err
	}
	_, err = req.Do()
	if err != nil {
		return fmt.Errorf("google: group api request failed %w", err)
	}
	b, err := json.Marshal(out)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}
