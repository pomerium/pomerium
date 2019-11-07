package identity // import "github.com/pomerium/pomerium/internal/identity"

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	oidc "github.com/pomerium/go-oidc"
	"golang.org/x/oauth2"

	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/internal/version"
)

// OktaProvider represents the Okta Identity Provider
//
// https://www.pomerium.io/docs/identity-providers.html#okta
type OktaProvider struct {
	*Provider

	RevokeURL string `json:"revocation_endpoint"`
	userAPI   *url.URL
}

// NewOktaProvider creates a new instance of Okta as an identity provider.
func NewOktaProvider(p *Provider) (*OktaProvider, error) {
	ctx := context.Background()
	if p.ProviderURL == "" {
		return nil, ErrMissingProviderURL
	}
	var err error
	p.provider, err = oidc.NewProvider(ctx, p.ProviderURL)
	if err != nil {
		return nil, err
	}
	if len(p.Scopes) == 0 {
		p.Scopes = []string{oidc.ScopeOpenID, "profile", "email", "groups", "offline_access"}
	}
	p.verifier = p.provider.Verifier(&oidc.Config{ClientID: p.ClientID})
	p.oauth = &oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: p.ClientSecret,
		Endpoint:     p.provider.Endpoint(),
		RedirectURL:  p.RedirectURL.String(),
		Scopes:       p.Scopes,
	}

	// okta supports a revocation endpoint
	oktaProvider := OktaProvider{Provider: p}
	if err := p.provider.Claims(&oktaProvider); err != nil {
		return nil, err
	}

	if p.ServiceAccount != "" {
		p.UserGroupFn = oktaProvider.UserGroups
		userAPI, err := urlutil.ParseAndValidateURL(p.ProviderURL)
		if err != nil {
			return nil, err
		}
		userAPI.Path = "/api/v1/users/"
		oktaProvider.userAPI = userAPI

	} else {
		log.Warn().Msg("identity/okta: api token provided, cannot retrieve groups")
	}

	return &oktaProvider, nil
}

// Revoke revokes the access token a given session state.
// https://developer.okta.com/docs/api/resources/oidc#revoke
func (p *OktaProvider) Revoke(ctx context.Context, token *oauth2.Token) error {
	params := url.Values{}
	params.Add("client_id", p.ClientID)
	params.Add("client_secret", p.ClientSecret)
	params.Add("token", token.AccessToken)
	params.Add("token_type_hint", "refresh_token")
	err := httputil.Client(ctx, http.MethodPost, p.RevokeURL, version.UserAgent(), nil, params, nil)
	if err != nil && err != httputil.ErrTokenRevoked {
		return err
	}
	return nil
}

// UserGroups fetches the groups of which the user is a member
// https://developer.okta.com/docs/reference/api/users/#get-user-s-groups
func (p *OktaProvider) UserGroups(ctx context.Context, s *sessions.State) ([]string, error) {
	var response []struct {
		ID      string `json:"id"`
		Profile struct {
			Name        string `json:"name"`
			Description string `json:"description"`
		} `json:"profile"`
	}

	headers := map[string]string{"Authorization": fmt.Sprintf("SSWS %s", p.ServiceAccount)}
	err := httputil.Client(ctx, http.MethodGet, fmt.Sprintf("%s/%s/groups", p.userAPI.String(), s.Subject), version.UserAgent(), headers, nil, &response)
	if err != nil {
		return nil, err
	}
	var groups []string
	for _, group := range response {
		log.Debug().Interface("group", group).Msg("identity/okta: group")
		groups = append(groups, group.ID)
	}
	return groups, nil
}
