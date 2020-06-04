// Package github implements OAuth2 based authentication for github
//
// https://www.pomerium.io/docs/identity-providers/github.html
package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"gopkg.in/square/go-jose.v2/jwt"

	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/identity/oauth"
	"github.com/pomerium/pomerium/internal/identity/oidc"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/version"
)

// Name identifies the GitHub identity provider
const Name = "github"

const (
	defaultProviderURL = "https://github.com"
	githubAPIURL       = "https://api.github.com"
	userPath           = "/user"
	teamPath           = "/user/teams"
	revokePath         = "/applications/%s/grant"
	emailPath          = "/user/emails"
	// https://developer.github.com/apps/building-oauth-apps/authorizing-oauth-apps
	authURL  = "/login/oauth/authorize"
	tokenURL = "/login/oauth/access_token"

	// since github doesn't implement oidc, we need this to refresh the user session
	refreshDeadline = time.Minute * 60
)

// https://developer.github.com/apps/building-oauth-apps/understanding-scopes-for-oauth-apps/
var defaultScopes = []string{"user:email", "read:org"}

// Provider is an implementation of the OAuth Provider.
type Provider struct {
	Oauth *oauth2.Config

	userEndpoint string
}

// New instantiates an OAuth2 provider for Github.
func New(ctx context.Context, o *oauth.Options) (*Provider, error) {
	p := Provider{}
	if o.ProviderURL == "" {
		o.ProviderURL = defaultProviderURL
	}
	if len(o.Scopes) == 0 {
		o.Scopes = defaultScopes
	}
	p.Oauth = &oauth2.Config{
		ClientID:     o.ClientID,
		ClientSecret: o.ClientSecret,
		Scopes:       o.Scopes,
		RedirectURL:  o.RedirectURL.String(),
		Endpoint: oauth2.Endpoint{
			AuthURL:  o.ProviderURL + authURL,
			TokenURL: o.ProviderURL + tokenURL,
		},
	}
	p.userEndpoint = githubAPIURL + userPath
	return &p, nil
}

// Authenticate creates an identity session with github from a authorization code, and follows up
// call to the user and user group endpoint with the
func (p *Provider) Authenticate(ctx context.Context, code string, v interface{}) (*oauth2.Token, error) {
	oauth2Token, err := p.Oauth.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("github: token exchange failed %v", err)
	}

	err = p.UpdateUserInfo(ctx, oauth2Token, v)
	if err != nil {
		return nil, err
	}

	return oauth2Token, nil
}

// UpdateUserInfo will get the user information from github and also retrieve the user's team(s)
//
// https://developer.github.com/v3/users/#get-the-authenticated-user
func (p *Provider) UpdateUserInfo(ctx context.Context, t *oauth2.Token, v interface{}) error {

	err := p.userInfo(ctx, t, v)
	if err != nil {
		return fmt.Errorf("github: could not retrieve user info %w", err)
	}

	err = p.userEmail(ctx, t, v)
	if err != nil {
		return fmt.Errorf("github: could not retrieve user email %w", err)
	}

	err = p.userTeams(ctx, t, v)
	if err != nil {
		return fmt.Errorf("github: could not retrieve groups %w", err)
	}

	return nil
}

// Refresh is a no-op for github, because github sessions never expire.
func (p *Provider) Refresh(ctx context.Context, t *oauth2.Token, v interface{}) (*oauth2.Token, error) {
	return t, nil
}

// userTeams returns a slice of teams the user belongs by making a request
// to github API
//
// https://developer.github.com/v3/teams/#list-user-teams
// https://developer.github.com/v3/auth/
func (p *Provider) userTeams(ctx context.Context, t *oauth2.Token, v interface{}) error {

	var response []struct {
		ID          json.Number `json:"id"`
		Name        string      `json:"name,omitempty"`
		URL         string      `json:"url,omitempty"`
		Slug        string      `json:"slug"`
		Description string      `json:"description,omitempty"`
		ReposURL    string      `json:"repos_url,omitempty"`
		Privacy     string      `json:"privacy,omitempty"`
	}

	headers := map[string]string{"Authorization": fmt.Sprintf("token %s", t.AccessToken)}
	teamURL := githubAPIURL + teamPath
	err := httputil.Client(ctx, http.MethodGet, teamURL, version.UserAgent(), headers, nil, &response)
	if err != nil {
		return err
	}
	log.Debug().Interface("teams", response).Msg("github: user teams")
	var out struct {
		Groups []string `json:"groups"`
	}
	for _, org := range response {
		out.Groups = append(out.Groups, org.ID.String())
	}
	b, err := json.Marshal(out)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// userEmail returns the primary email of the user by making
// a query to github API.
//
// https://developer.github.com/v3/users/emails/#list-email-addresses-for-a-user
// https://developer.github.com/v3/auth/
func (p *Provider) userEmail(ctx context.Context, t *oauth2.Token, v interface{}) error {
	// response represents the github user email
	// https://developer.github.com/v3/users/emails/#response
	var response []struct {
		Email      string `json:"email"`
		Verified   bool   `json:"verified"`
		Primary    bool   `json:"primary"`
		Visibility string `json:"visibility"`
	}
	headers := map[string]string{"Authorization": fmt.Sprintf("token %s", t.AccessToken)}
	emailURL := githubAPIURL + emailPath
	err := httputil.Client(ctx, http.MethodGet, emailURL, version.UserAgent(), headers, nil, &response)
	if err != nil {
		return err
	}
	var out struct {
		Email    string `json:"email"`
		Verified bool   `json:"email_verified"`
	}
	log.Debug().Interface("emails", response).Msg("github: user emails")
	for _, email := range response {
		if email.Primary && email.Verified {
			out.Email = email.Email
			out.Verified = true
			break
		}
	}
	b, err := json.Marshal(out)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func (p *Provider) userInfo(ctx context.Context, t *oauth2.Token, v interface{}) error {
	var response struct {
		ID        int    `json:"id"`
		Login     string `json:"login"`
		Name      string `json:"name"`
		AvatarURL string `json:"avatar_url,omitempty"`
	}

	headers := map[string]string{
		"Authorization": fmt.Sprintf("token %s", t.AccessToken),
		"Accept":        "application/vnd.github.v3+json",
	}
	err := httputil.Client(ctx, http.MethodGet, p.userEndpoint, version.UserAgent(), headers, nil, &response)
	if err != nil {
		return err
	}
	var out struct {
		Subject string `json:"sub"`
		Name    string `json:"name,omitempty"`
		User    string `json:"user"`
		Picture string `json:"picture,omitempty"`
		// needs to be set manually
		Expiry *jwt.NumericDate `json:"exp,omitempty"`
	}

	out.User = response.Login
	out.Subject = response.Login
	out.Name = response.Name
	out.Picture = response.AvatarURL
	// set the session expiry
	out.Expiry = jwt.NewNumericDate(time.Now().Add(refreshDeadline))
	b, err := json.Marshal(out)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// Revoke method will remove all the github grants the user
// gave pomerium application during authorization.
//
// https://developer.github.com/v3/apps/oauth_applications/#delete-an-app-authorization
func (p *Provider) Revoke(ctx context.Context, token *oauth2.Token) error {
	// build the basic authentication request
	basicAuth := url.UserPassword(p.Oauth.ClientID, p.Oauth.ClientSecret)
	revokeURL := url.URL{
		Scheme: "https",
		User:   basicAuth,
		Host:   "api.github.com",
		Path:   fmt.Sprintf(revokePath, p.Oauth.ClientID),
	}
	reqBody := strings.NewReader(fmt.Sprintf(`{"access_token": "%s"}`, token.AccessToken))
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, revokeURL.String(), reqBody)
	if err != nil {
		return errors.New("github: could not create revoke request")
	}

	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

// GetSignInURL returns a URL to OAuth 2.0 provider's consent page
// that asks for permissions for the required scopes explicitly.
func (p *Provider) GetSignInURL(state string) string {
	return p.Oauth.AuthCodeURL(state, oauth2.AccessTypeOffline)
}

// LogOut is not implemented by github.
func (p *Provider) LogOut() (*url.URL, error) {
	return nil, oidc.ErrSignoutNotImplemented
}
