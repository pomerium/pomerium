package identity // import "github.com/pomerium/pomerium/internal/identity"

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/oauth2"

	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/internal/version"
)

const defaultGithubProviderURL = "https://github.com"
const authAPI = "login/oauth/authorize"
const tokenAPI = "login/oauth/access_token"
const emailAPI = "user/emails"
const orgsAPI = "user/orgs"
const teamAPI = "user/teams"
const userAPI = "user"

var defaultGithubScopes = []string{"user:email", "read:org"}

type GithubProvider struct {
	*Provider

	// baseURL would be different in the enterprise version
	baseURL           *url.URL
	authURL           *url.URL
	tokenURL          *url.URL
	userEmailEndpoint *url.URL
	userOrgsEndpoint  *url.URL
	userTeamsEndpoint *url.URL
	userEndpoint      *url.URL
}

// Register a new oauth application: https://github.com/settings/applications/new
// https://developer.github.com/apps/building-oauth-apps/authorizing-oauth-apps/
// https://developer.github.com/v3/oauth_authorizations/#create-a-new-authorization
func NewGithubProvider(p *Provider) (*GithubProvider, error) {
	if p.ProviderURL == "" {
		p.ProviderURL = defaultGithubProviderURL
	}
	if len(p.Scopes) == 0 {
		p.Scopes = defaultGithubScopes
	}
	var err error
	var gp GithubProvider
	gp.baseURL, err = urlutil.ParseAndValidateURL(p.ProviderURL)
	if err != nil {
		return nil, fmt.Errorf("identity/github: couldn't parse provider url %v", err)
	}
	gp.authURL = &url.URL{Path: authAPI, Scheme: gp.baseURL.Scheme, Host: gp.baseURL.Host}
	gp.tokenURL = &url.URL{Path: tokenAPI, Scheme: gp.baseURL.Scheme, Host: gp.baseURL.Host}
	gp.userEmailEndpoint = &url.URL{Path: emailAPI, Scheme: gp.baseURL.Scheme, Host: "api." + gp.baseURL.Host}
	gp.userOrgsEndpoint = &url.URL{Path: orgsAPI, Scheme: gp.baseURL.Scheme, Host: "api." + gp.baseURL.Host}
	gp.userTeamsEndpoint = &url.URL{Path: teamAPI, Scheme: gp.baseURL.Scheme, Host: "api." + gp.baseURL.Host}
	gp.userEndpoint = &url.URL{Path: userAPI, Scheme: gp.baseURL.Scheme, Host: "api." + gp.baseURL.Host}

	p.oauth = &oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: p.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  gp.authURL.String(),
			TokenURL: gp.tokenURL.String(),
		},
		RedirectURL: p.RedirectURL.String(),
		Scopes:      p.Scopes,
	}
	gp.Provider = p
	return &gp, nil
}

// Authenticate creates an identity session with google from a authorization code, and follows up
// call to the admin/group api to check what groups the user is in.
func (p *GithubProvider) Authenticate(ctx context.Context, code string) (*sessions.SessionState, error) {
	resp, err := p.oauth.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("identity/google: token exchange failed %v", err)
	}
	var session sessions.SessionState
	session.AccessToken = resp.AccessToken

	// THIS IS ALL VERY VERY WEIRD; why doesn't github use OIDC?
	// github doesn't have a refresh token!? AccessToken never expires
	session.RefreshToken = resp.AccessToken
	session.IDToken = resp.AccessToken
	session.RefreshDeadline = resp.Expiry
	if (session.RefreshDeadline == time.Time{}) {
		session.RefreshDeadline = time.Now().Add(1 * time.Hour).Truncate(time.Second)
	}
	return p.fetchUserInfo(ctx, &session)
}

func (p *GithubProvider) Validate(ctx context.Context, idToken string) (bool, error) {
	return true, nil
}

func (p *GithubProvider) fetchUserInfo(ctx context.Context, s *sessions.SessionState) (*sessions.SessionState, error) {
	if s.AccessToken == "" {
		return nil, fmt.Errorf("access token cannot be empty")
	}
	var err error
	s.Email, err = p.userEmail(ctx, s.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("couldn't get user's email %v", err)
	}
	s.User, err = p.userName(ctx, s.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("couldn't get user's username %v", err)
	}
	orgs, err := p.userOrganizations(ctx, s.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("couldn't get user's organization %v", err)
	}
	teams, err := p.userOrganizationTeams(ctx, s.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("couldn't get user's teams %v", err)
	}
	s.Groups = append(orgs, teams...)
	return s, nil
}
func (p *GithubProvider) Refresh(ctx context.Context, s *sessions.SessionState) (*sessions.SessionState, error) {

	return p.fetchUserInfo(ctx, s)
}

// https://developer.github.com/v3/orgs/#list-your-organizations
func (p *GithubProvider) userOrganizations(ctx context.Context, accessToken string) ([]string, error) {
	var groups []string
	var response []struct {
		Description string `json:"description"`
		ID          int    `json:"id"`
		Login       string `json:"login"`
		URL         string `json:"url"`
	}
	headers := map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", accessToken),
		"Accept":        "application/vnd.github.v3+json",
	}
	err := httputil.Client(http.MethodGet, p.userOrgsEndpoint.String(), version.UserAgent(), headers, nil, &response)
	if err != nil {
		return groups, err
	}
	for _, org := range response {
		groups = append(groups, org.Login)
	}
	return groups, nil
}
func (p *GithubProvider) userOrganizationTeams(ctx context.Context, accessToken string) ([]string, error) {
	var groups []string
	var response []struct {
		CreatedAt    time.Time `json:"created_at"`
		Description  string    `json:"description"`
		ID           int       `json:"id"`
		Name         string    `json:"name"`
		Organization struct {
			Login string `json:"login"`
		} `json:"organization"`
	}
	headers := map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", accessToken),
		"Accept":        "application/vnd.github.v3+json",
	}
	err := httputil.Client(http.MethodGet, p.userTeamsEndpoint.String(), version.UserAgent(), headers, nil, &response)
	if err != nil {
		return groups, err
	}
	for _, org := range response {
		groups = append(groups, fmt.Sprintf("%s/%s", org.Organization.Login, org.Name))
	}
	return groups, nil
}

// userEmail gets all your email addresses, and specifies which one is visible to the public.
// This endpoint is accessible with the user:email scope.
func (p *GithubProvider) userEmail(ctx context.Context, accessToken string) (string, error) {
	var response []struct {
		Email      string `json:"email"`
		Verified   bool   `json:"verified"`
		Primary    bool   `json:"primary"`
		Visibility string `json:"visibility"`
	}
	headers := map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", accessToken),
		"Accept":        "application/vnd.github.v3+json",
	}
	err := httputil.Client(http.MethodGet, p.userEmailEndpoint.String(), version.UserAgent(), headers, nil, &response)
	if err != nil {
		return "", err
	}
	for _, email := range response {
		if email.Verified && email.Primary {
			return email.Email, nil
		}
	}
	return "", fmt.Errorf("could not find a primary, verified email for user")
}

func (p *GithubProvider) userName(ctx context.Context, accessToken string) (string, error) {
	var response struct {
		ID    int    `json:"id"`
		Login string `json:"login"`
	}
	headers := map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", accessToken),
		"Accept":        "application/vnd.github.v3+json",
	}
	err := httputil.Client(http.MethodGet, p.userEndpoint.String(), version.UserAgent(), headers, nil, &response)
	if err != nil {
		return "", err
	}
	return response.Login, nil
}
