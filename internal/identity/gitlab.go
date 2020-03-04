package identity // import "github.com/pomerium/pomerium/internal/identity"

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	oidc "github.com/coreos/go-oidc"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/version"
	"golang.org/x/oauth2"
)

const (
	defaultGitLabProviderURL = "https://gitlab.com"
	revokeURL                = "https://gitlab.com/oauth/revoke"
	defaultGitLabGroupURL    = "https://gitlab.com/api/v4/groups"
)

// GitLabProvider is an implementation of the OAuth Provider
type GitLabProvider struct {
	*Provider
	RevokeURL string `json:"revocation_endpoint"`
}

// NewGitLabProvider returns a new GitLabProvider.
// https://www.pomerium.io/docs/identity-providers/gitlab.html
func NewGitLabProvider(p *Provider) (*GitLabProvider, error) {
	ctx := context.Background()

	if p.ProviderURL == "" {
		p.ProviderURL = defaultGitLabProviderURL
	}

	var err error
	p.provider, err = oidc.NewProvider(ctx, p.ProviderURL)
	if err != nil {
		return nil, err
	}

	if len(p.Scopes) == 0 {
		p.Scopes = []string{oidc.ScopeOpenID, "api", "read_user", "profile", "email"}
	}

	p.verifier = p.provider.Verifier(&oidc.Config{ClientID: p.ClientID})
	p.oauth = &oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: p.ClientSecret,
		Endpoint:     p.provider.Endpoint(),
		RedirectURL:  p.RedirectURL.String(),
		Scopes:       p.Scopes,
	}
	gp := &GitLabProvider{
		Provider:  p,
		RevokeURL: revokeURL,
	}

	if err := p.provider.Claims(&gp); err != nil {
		return nil, err
	}

	return gp, nil
}

// Authenticate creates an identity session with gitlab from a authorization code, and makes
// a call to the userinfo endpoint to get the information of the user.
func (p GitLabProvider) Authenticate(ctx context.Context, code string) (*sessions.State, error) {
	oauth2Token, err := p.oauth.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("internal/gitlab: token exchange failed: %w", err)
	}

	idToken, err := p.IdentityFromToken(ctx, oauth2Token)
	if err != nil {
		return nil, err
	}

	s, err := sessions.NewStateFromTokens(idToken, oauth2Token, p.RedirectURL.Hostname())
	if err != nil {
		return nil, err
	}

	var claims struct {
		ID          string `json:"sub"`
		UserInfoURL string `json:"userinfo_endpoint"`
	}

	if err := p.provider.Claims(&claims); err == nil && claims.UserInfoURL != "" {
		userInfo, err := p.provider.UserInfo(ctx, oauth2.StaticTokenSource(oauth2Token))
		if err != nil {
			return nil, fmt.Errorf("internal/gitlab: could not retrieve user info %w", err)
		}
		if err := userInfo.Claims(&s); err != nil {
			return nil, err
		}
	}

	if p.UserGroupFn != nil {
		s.Groups, err = p.UserGroupFn(ctx, s)
		if err != nil {
			return nil, fmt.Errorf("internal/gitlab: could not retrieve groups %w", err)
		}
	}

	return s, nil
}

// UserGroups returns a slice of groups for the user.
//
// By default, this request returns 20 results at a time because the API results are paginated.
// https://docs.gitlab.com/ee/api/groups.html#list-groups
func (p *GitLabProvider) UserGroups(ctx context.Context, s *sessions.State) ([]string, error) {
	if s == nil || s.AccessToken == nil {
		return nil, errors.New("identity/gitlab: user session cannot be empty")
	}

	var response []struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Path        string `json:"path"`
		Description string `json:"description"`
		Visibility  string `json:"visibility"`
	}
	headers := map[string]string{"Authorization": fmt.Sprintf("Bearer %s", s.AccessToken.AccessToken)}
	err := httputil.Client(ctx, http.MethodGet, defaultGitLabGroupURL, version.UserAgent(), headers, nil, &response)
	if err != nil {
		return nil, err
	}

	var groups []string
	for _, group := range response {
		groups = append(groups, group.Name)
	}

	return groups, nil
}

// Revoke attempts to revoke session access via revocation endpoint
// https://docs.gitlab.com/ee/user/profile/personal_access_tokens.html#revoking-a-personal-access-token
func (p *GitLabProvider) Revoke(ctx context.Context, token *oauth2.Token) error {
	params := url.Values{}
	params.Add("access_token", token.AccessToken)

	err := httputil.Client(ctx, http.MethodPost, p.RevokeURL, version.UserAgent(), nil, params, nil)
	if err != nil && err != httputil.ErrTokenRevoked {
		return err
	}

	return nil
}
