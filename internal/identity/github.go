package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/version"

	"golang.org/x/oauth2"
	"gopkg.in/square/go-jose.v2/jwt"
)

const (
	defaultGitHubProviderURL = "https://github.com"
	githubAuthURL            = "/login/oauth/authorize"
	githubUserURL            = "https://api.github.com/user"
	githubUserTeamURL        = "https://api.github.com/user/teams"
	githubRevokeURL          = "https://github.com/oauth/revoke"
	githubUserEmailURL       = "https://api.github.com/user/emails"

	// since github doesn't implement oidc, we need this to refresh the user session
	refreshDeadline = time.Minute * 60
)

// GitHubProvider is an implementation of the OAuth Provider.
type GitHubProvider struct {
	*Provider

	authURL      string
	tokenURL     string
	userEndpoint string

	RevokeURL string `json:"revocation_endpoint"`
}

// NewGitHubProvider returns a new GitHubProvider.
func NewGitHubProvider(p *Provider) (*GitHubProvider, error) {
	gp := &GitHubProvider{
		authURL:      defaultGitHubProviderURL + githubAuthURL,
		tokenURL:     defaultGitHubProviderURL + "/login/oauth/access_token",
		userEndpoint: githubUserURL,
		RevokeURL:    githubRevokeURL,
	}

	if p.ProviderURL == "" {
		p.ProviderURL = defaultGitHubProviderURL
	}

	if len(p.Scopes) == 0 {
		p.Scopes = []string{"user:email", "read:org"}
	}

	p.oauth = &oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: p.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  gp.authURL,
			TokenURL: gp.tokenURL,
		},
		RedirectURL: p.RedirectURL.String(),
		Scopes:      p.Scopes,
	}
	gp.Provider = p

	return gp, nil
}

// Authenticate creates an identity session with github from a authorization code, and follows up
// call to the user and user group endpoint with the
func (p *GitHubProvider) Authenticate(ctx context.Context, code string) (*sessions.State, error) {
	resp, err := p.oauth.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("identity/github: token exchange failed %v", err)
	}

	s := &sessions.State{
		AccessToken: &oauth2.Token{
			AccessToken: resp.AccessToken,
			TokenType:   resp.TokenType,
		},
		AccessTokenID: resp.AccessToken,
	}

	err = p.updateSessionState(ctx, s)
	if err != nil {
		return nil, err
	}

	return s, nil
}

// updateSessionState will get the user information from github and also retrieve the user's team(s)
//
// https://developer.github.com/v3/users/#get-the-authenticated-user
func (p *GitHubProvider) updateSessionState(ctx context.Context, s *sessions.State) error {
	if s == nil || s.AccessToken == nil {
		return errors.New("identity/github: user session cannot be empty")
	}
	accessToken := s.AccessToken.AccessToken

	err := p.userInfo(ctx, accessToken, s)
	if err != nil {
		return fmt.Errorf("identity/github: could not user info %w", err)
	}

	err = p.userEmail(ctx, accessToken, s)
	if err != nil {
		return fmt.Errorf("identity/github: could not retrieve user email %w", err)
	}

	err = p.userTeams(ctx, accessToken, s)
	if err != nil {
		return fmt.Errorf("identity/github: could not retrieve groups %w", err)
	}

	return nil
}

// Refresh renews a user's session by making a new userInfo request.
func (p *GitHubProvider) Refresh(ctx context.Context, s *sessions.State) (*sessions.State, error) {
	if s.AccessToken == nil {
		return nil, errors.New("identity/github: missing oauth2 access token")
	}
	if err := p.updateSessionState(ctx, s); err != nil {
		return nil, err
	}
	return s, nil
}

// userTeams returns a slice of teams the user belongs by making a request
// to github API
//
// https://developer.github.com/v3/teams/#list-user-teams
// https://developer.github.com/v3/auth/
func (p *GitHubProvider) userTeams(ctx context.Context, at string, s *sessions.State) error {

	var response []struct {
		ID          json.Number `json:"id"`
		Name        string      `json:"name,omitempty"`
		URL         string      `json:"url,omitempty"`
		Slug        string      `json:"slug"`
		Description string      `json:"description,omitempty"`
		ReposURL    string      `json:"repos_url,omitempty"`
		Privacy     string      `json:"privacy,omitempty"`
	}

	headers := map[string]string{"Authorization": fmt.Sprintf("token %s", at)}
	err := httputil.Client(ctx, http.MethodGet, githubUserTeamURL, version.UserAgent(), headers, nil, &response)
	if err != nil {
		return err
	}

	log.Debug().Interface("teams", response).Msg("identity/github: user teams")

	s.Groups = nil
	for _, org := range response {
		s.Groups = append(s.Groups, org.ID.String())
	}

	return nil
}

// userEmail returns the primary email of the user by making
// a query to github API.
//
// https://developer.github.com/v3/users/emails/#list-email-addresses-for-a-user
// https://developer.github.com/v3/auth/
func (p *GitHubProvider) userEmail(ctx context.Context, at string, s *sessions.State) error {
	// response represents the github user email
	// https://developer.github.com/v3/users/emails/#response
	var response []struct {
		Email      string `json:"email"`
		Verified   bool   `json:"verified"`
		Primary    bool   `json:"primary"`
		Visibility string `json:"visibility"`
	}
	headers := map[string]string{"Authorization": fmt.Sprintf("token %s", at)}
	err := httputil.Client(ctx, http.MethodGet, githubUserEmailURL, version.UserAgent(), headers, nil, &response)
	if err != nil {
		return err
	}

	log.Debug().Interface("emails", response).Msg("identity/github: user emails")
	for _, email := range response {
		if email.Primary && email.Verified {
			s.Email = email.Email
			s.EmailVerified = true
			return nil
		}
	}
	return nil
}

func (p *GitHubProvider) userInfo(ctx context.Context, at string, s *sessions.State) error {
	var response struct {
		ID        int    `json:"id"`
		Login     string `json:"login"`
		Name      string `json:"name"`
		Email     string `json:"email"`
		AvatarURL string `json:"avatar_url,omitempty"`
	}

	headers := map[string]string{
		"Authorization": fmt.Sprintf("token %s", at),
		"Accept":        "application/vnd.github.v3+json",
	}
	err := httputil.Client(ctx, http.MethodGet, p.userEndpoint, version.UserAgent(), headers, nil, &response)
	if err != nil {
		return err
	}

	s.User = response.Login
	s.Name = response.Name
	s.Picture = response.AvatarURL
	// set the session expiry
	s.Expiry = jwt.NewNumericDate(time.Now().Add(refreshDeadline))
	return nil
}
