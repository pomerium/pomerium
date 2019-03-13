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

// defaultAzureProviderURL Users with both a personal Microsoft
// account and a work or school account from Azure Active Directory (Azure AD)
// an sign in to the application.
const defaultAzureProviderURL = "https://login.microsoftonline.com/common"
const defaultAzureGroupURL = "https://graph.microsoft.com/v1.0/me/memberOf"

// AzureProvider is an implementation of the Provider interface
type AzureProvider struct {
	*Provider
	// non-standard oidc fields
	RevokeURL *url.URL
}

// NewAzureProvider returns a new AzureProvider and sets the provider url endpoints.
// https://www.pomerium.io/docs/identity-providers.html#azure-active-directory
func NewAzureProvider(p *Provider) (*AzureProvider, error) {
	ctx := context.Background()
	if p.ProviderURL == "" {
		p.ProviderURL = defaultAzureProviderURL
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

	azureProvider := &AzureProvider{
		Provider: p,
	}
	// azure has a "end session endpoint"
	var claims struct {
		RevokeURL string `json:"end_session_endpoint"`
	}
	if err := p.provider.Claims(&claims); err != nil {
		return nil, err
	}
	azureProvider.RevokeURL, err = url.Parse(claims.RevokeURL)
	if err != nil {
		return nil, err
	}

	return azureProvider, nil
}

// Authenticate creates an identity session with azure from a authorization code, and follows up
// call to the groups api to check what groups the user is in.
func (p *AzureProvider) Authenticate(code string) (*sessions.SessionState, error) {
	ctx := context.Background()
	// convert authorization code into a token
	oauth2Token, err := p.oauth.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("identity/microsoft: token exchange failed %v", err)
	}

	// id_token contains claims about the authenticated user
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("identity/microsoft: response did not contain an id_token")
	}
	// Parse and verify ID Token payload.
	idToken, err := p.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("identity/microsoft: could not verify id_token %v", err)
	}

	var claims struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	}
	// parse claims from the raw, encoded jwt token
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("identity/microsoft: failed to parse id_token claims %v", err)
	}

	// google requires additional call to retrieve groups.
	groups, err := p.UserGroups(ctx, claims.Email)
	if err != nil {
		return nil, fmt.Errorf("identity/microsoft: could not retrieve groups %v", err)
	}

	return &sessions.SessionState{
		IDToken:          rawIDToken,
		AccessToken:      oauth2Token.AccessToken,
		RefreshToken:     oauth2Token.RefreshToken,
		RefreshDeadline:  oauth2Token.Expiry.Truncate(time.Second),
		LifetimeDeadline: sessions.ExtendDeadline(p.SessionLifetimeTTL),
		Email:            claims.Email,
		User:             idToken.Subject,
		Groups:           groups,
	}, nil
}

// Revoke revokes the access token a given session state.
// https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-protocols-oidc#send-a-sign-out-request
func (p *AzureProvider) Revoke(token string) error {
	params := url.Values{}
	params.Add("token", token)
	err := httputil.Client(http.MethodPost, p.RevokeURL.String(), version.UserAgent(), nil, params, nil)
	if err != nil && err != httputil.ErrTokenRevoked {
		return err
	}
	return nil
}

// GetSignInURL returns the sign in url with typical oauth parameters
func (p *AzureProvider) GetSignInURL(state string) string {
	return p.oauth.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.ApprovalForce)
}

// Refresh renews a user's session using an oid refresh token without reprompting the user.
// Group membership is also refreshed.
// https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokens
func (p *AzureProvider) Refresh(ctx context.Context, s *sessions.SessionState) (*sessions.SessionState, error) {
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

// UserGroups returns a slice of group names a given user is in.
// `Directory.Read.All` is required.
// https://docs.microsoft.com/en-us/graph/api/resources/directoryobject?view=graph-rest-1.0
// https://docs.microsoft.com/en-us/graph/api/user-list-memberof?view=graph-rest-1.0
func (p *AzureProvider) UserGroups(ctx context.Context, accessToken string) ([]string, error) {
	var response struct {
		Groups []struct {
			ID              string    `json:"id"`
			Description     string    `json:"description,omitempty"`
			DisplayName     string    `json:"displayName"`
			CreatedDateTime time.Time `json:"createdDateTime,omitempty"`
			GroupTypes      []string  `json:"groupTypes,omitempty"`
		} `json:"value"`
	}
	headers := map[string]string{"Authorization": fmt.Sprintf("Bearer %s", accessToken)}
	err := httputil.Client(http.MethodGet, defaultAzureGroupURL, version.UserAgent(), headers, nil, &response)
	if err != nil {
		return nil, err
	}
	var groups []string
	for _, group := range response.Groups {
		log.Debug().Str("DisplayName", group.DisplayName).Str("ID", group.ID).Msg("identity/microsoft: group")
		groups = append(groups, group.DisplayName)
	}
	return groups, nil
}
