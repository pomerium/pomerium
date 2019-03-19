package identity // import "github.com/pomerium/pomerium/internal/identity"

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	oidc "github.com/pomerium/go-oidc"
	"golang.org/x/oauth2"

	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/version"
)

// OneLoginProvider provides a standard, OpenID Connect implementation
// of an authorization identity provider.
type OneLoginProvider struct {
	*Provider

	// non-standard oidc fields
	RevokeURL  *url.URL
	AdminCreds *credentialsFile
}

const defaultOneLoginProviderURL = "https://openid-connect.onelogin.com/oidc"

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

	// okta supports a revocation endpoint
	var claims struct {
		RevokeURL string `json:"revocation_endpoint"`
	}
	if err := p.provider.Claims(&claims); err != nil {
		return nil, err
	}
	OneLoginProvider := OneLoginProvider{Provider: p}

	OneLoginProvider.RevokeURL, err = url.Parse(claims.RevokeURL)
	if err != nil {
		return nil, err
	}

	return &OneLoginProvider, nil
}

// Revoke revokes the access token a given session state.
// https://developers.onelogin.com/openid-connect/api/revoke-session
func (p *OneLoginProvider) Revoke(token string) error {
	params := url.Values{}
	params.Add("client_id", p.ClientID)
	params.Add("client_secret", p.ClientSecret)
	params.Add("token", token)
	params.Add("token_type_hint", "access_token")
	err := httputil.Client("POST", p.RevokeURL.String(), version.UserAgent(), nil, params, nil)
	if err != nil && err != httputil.ErrTokenRevoked {
		log.Error().Err(err).Msg("authenticate/providers: failed to revoke session")
		return err
	}
	return nil
}

// GetSignInURL returns the sign in url with typical oauth parameters
func (p *OneLoginProvider) GetSignInURL(state string) string {
	return p.oauth.AuthCodeURL(state, oauth2.AccessTypeOffline)
}

// Refresh renews a user's session using an oid refresh token without reprompting the user.
// Group membership is also refreshed.
// https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokens
func (p *OneLoginProvider) Refresh(ctx context.Context, s *sessions.SessionState) (*sessions.SessionState, error) {
	if s.RefreshToken == "" {
		return nil, errors.New("identity/microsoft: missing refresh token")
	}
	t := oauth2.Token{RefreshToken: s.RefreshToken}
	newToken, err := p.oauth.TokenSource(ctx, &t).Token()
	if err != nil {
		log.Error().Err(err).Msg("identity/microsoft: refresh failed")
		return nil, err
	}
	s.AccessToken = newToken.AccessToken
	s.RefreshDeadline = newToken.Expiry.Truncate(time.Second)
	s.Groups, err = p.UserGroups(ctx, s.AccessToken)
	if err != nil {
		log.Error().Err(err).Msg("identity/microsoft: refresh failed")
		return nil, err
	}
	return s, nil
}

const defaultOneloginGroupURL = "https://openid-connect.onelogin.com/oidc/me"

// UserGroups returns a slice of group names a given user is in.
// https://developers.onelogin.com/openid-connect/api/user-info
func (p *OneLoginProvider) UserGroups(ctx context.Context, accessToken string) ([]string, error) {
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
	headers := map[string]string{"Authorization": fmt.Sprintf("Bearer %s", accessToken)}
	err := httputil.Client(http.MethodGet, defaultOneloginGroupURL, version.UserAgent(), headers, nil, &response)
	if err != nil {
		return nil, err
	}
	var groups []string
	for _, group := range response.Groups {
		log.Debug().Str("ID", group).Msg("identity/onelogin: group")
		groups = append(groups, group)
	}
	return groups, nil
}
