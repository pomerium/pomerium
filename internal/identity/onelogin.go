package identity // import "github.com/pomerium/pomerium/internal/identity"

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	oidc "github.com/coreos/go-oidc"
	"golang.org/x/oauth2"

	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/version"
)

const defaultOneLoginProviderURL = "https://openid-connect.onelogin.com/oidc"
const defaultOneloginGroupURL = "https://openid-connect.onelogin.com/oidc/me"

// OneLoginProvider provides a standard, OpenID Connect implementation
// of an authorization identity provider.
type OneLoginProvider struct {
	*Provider

	// non-standard oidc fields
	RevokeURL string `json:"revocation_endpoint"`
}

// NewOneLoginProvider creates a new instance of an OpenID Connect provider.
func NewOneLoginProvider(p *Provider) (*OneLoginProvider, error) {
	ctx := context.Background()
	if p.ProviderURL == "" {
		p.ProviderURL = defaultOneLoginProviderURL
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

	olProvider := OneLoginProvider{Provider: p}

	if err := p.provider.Claims(&olProvider); err != nil {
		return nil, err
	}

	p.UserGroupFn = olProvider.UserGroups

	return &olProvider, nil
}

// Revoke revokes the access token a given session state.
// https://developers.onelogin.com/openid-connect/api/revoke-session
func (p *OneLoginProvider) Revoke(ctx context.Context, token *oauth2.Token) error {
	params := url.Values{}
	params.Add("client_id", p.ClientID)
	params.Add("client_secret", p.ClientSecret)
	params.Add("token", token.AccessToken)
	params.Add("token_type_hint", "access_token")
	err := httputil.Client(ctx, http.MethodPost, p.RevokeURL, version.UserAgent(), nil, params, nil)
	if err != nil && err != httputil.ErrTokenRevoked {
		return fmt.Errorf("identity/onelogin: revocation error %w", err)
	}
	return nil
}

// UserGroups returns a slice of group names a given user is in.
// https://developers.onelogin.com/openid-connect/api/user-info
func (p *OneLoginProvider) UserGroups(ctx context.Context, s *sessions.State) ([]string, error) {
	if s == nil || s.AccessToken == nil {
		return nil, errors.New("identity/onelogin: session cannot be nil")
	}
	var response struct {
		User              string    `json:"sub"`
		Email             string    `json:"email"`
		PreferredUsername string    `json:"preferred_username"`
		Name              string    `json:"name"`
		UpdatedAt         time.Time `json:"updated_at"`
		GivenName         string    `json:"given_name"`
		FamilyName        string    `json:"family_name"`
		Groups            []string  `json:"groups"`
	}
	headers := map[string]string{"Authorization": fmt.Sprintf("Bearer %s", s.AccessToken.AccessToken)}
	err := httputil.Client(ctx, http.MethodGet, defaultOneloginGroupURL, version.UserAgent(), headers, nil, &response)
	if err != nil {
		return nil, err
	}
	return response.Groups, nil
}
