package identity // import "github.com/pomerium/pomerium/internal/identity"

import (
	"context"
	"fmt"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/sessions"
	"net/http"
	"net/url"
)
import oidc "github.com/pomerium/go-oidc"
import "golang.org/x/oauth2"

// OIDCProvider provides a standard, OpenID Connect implementation
// of an authorization identity provider.
// https://openid.net/specs/openid-connect-core-1_0.html
type GitLabProvider struct {
	*Provider
	Subject       string `json:"sub"`
	Profile       string `json:"profile"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	// contains filtered or unexported fields
}

// NewGitLabProvider creates a new instance of a GitLab provider.
func NewGitLabProvider(p *Provider) (*GitLabProvider, error) {
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
		p.Scopes = []string{oidc.ScopeOpenID, "profile", "email", "offline_access"}
	}
	p.verifier = p.provider.Verifier(&oidc.Config{ClientID: p.ClientID})
	p.oauth = &oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: p.ClientSecret,
		Endpoint:     p.provider.Endpoint(),
		RedirectURL:  p.RedirectURL.String(),
		Scopes:       p.Scopes,
	}
	return &GitLabProvider{Provider: p}, nil
}

// Revoke revokes the access token a given session state.
// https://developer.okta.com/docs/api/resources/oidc#revoke
//func (p *GitLabProvider) Revoke(ctx context.Context, token *oauth2.Token) error {
//	return nil
//}

// Authenticate is a mocked providers function.
func (gp GitLabProvider) Authenticate(ctx context.Context, code string) (*sessions.State, error) {
	oauth2Token, err := gp.oauth.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("internal/identity: token exchange failed: %w", err)
	}
	idToken, err := gp.IdentityFromToken(ctx, oauth2Token)
	if err != nil {
		return nil, err
	}

	var userInfo struct {
		ID       string   `json:"sub"`
		Name     string   `json:"name"`
		Nickname string   `json:"nickname"`
		Email    string   `json:"email"`
		Groups   []string `json:"groups"`
	}

	params := url.Values{}
	params.Add("access_token", oauth2Token.AccessToken)

	err = httputil.Client(ctx, http.MethodGet, gp.ProviderURL+"/oauth/userinfo", "nil", nil, params, &userInfo)
	if err != nil && err != httputil.ErrTokenRevoked {
		return nil, fmt.Errorf("identity/onelogin: revocation error %w", err)
	}

	s, err := sessions.NewStateFromTokens(idToken, oauth2Token, gp.RedirectURL.Hostname())

	if err != nil {
		return nil, err
	}

	s.Email = userInfo.Email
	s.Groups = userInfo.Groups
	s.User = userInfo.Nickname
	s.Name = userInfo.Name

	return s, nil
}
