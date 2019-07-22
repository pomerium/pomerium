package identity // import "github.com/pomerium/pomerium/internal/identity"

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"time"

	oidc "github.com/pomerium/go-oidc"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/jwt"
	admin "google.golang.org/api/admin/directory/v1"

	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/version"
)

const defaultGoogleProviderURL = "https://accounts.google.com"

// JWTTokenURL is Google's OAuth 2.0 token URL to use with the JWT flow.
const JWTTokenURL = "https://accounts.google.com/o/oauth2/token"

// GoogleProvider is an implementation of the Provider interface.
type GoogleProvider struct {
	*Provider
	// non-standard oidc fields
	RevokeURL *url.URL
	apiClient *admin.Service
}

// NewGoogleProvider instantiates an OpenID Connect (OIDC) session with Google.
func NewGoogleProvider(p *Provider) (*GoogleProvider, error) {
	ctx := context.Background()
	if p.ProviderURL == "" {
		p.ProviderURL = defaultGoogleProviderURL
	}
	var err error
	p.provider, err = oidc.NewProvider(ctx, p.ProviderURL)
	if err != nil {
		return nil, err
	}
	// Google rejects the offline scope favoring "access_type=offline"
	// as part of the authorization request instead.
	if len(p.Scopes) == 0 {
		p.Scopes = []string{oidc.ScopeOpenID, "profile", "email"}
	}
	p.verifier = p.provider.Verifier(&oidc.Config{ClientID: p.ClientID})
	p.oauth = &oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: p.ClientSecret,
		Endpoint:     p.provider.Endpoint(),
		RedirectURL:  p.RedirectURL.String(),
		Scopes:       p.Scopes,
	}

	gp := &GoogleProvider{
		Provider: p,
	}
	// google supports a revocation endpoint
	var claims struct {
		RevokeURL string `json:"revocation_endpoint"`
	}

	// build api client to make group membership api calls
	if err := p.provider.Claims(&claims); err != nil {
		return nil, err
	}
	// if service account set, configure admin sdk calls
	if p.ServiceAccount != "" {
		apiCreds, err := base64.StdEncoding.DecodeString(p.ServiceAccount)
		if err != nil {
			return nil, fmt.Errorf("identity/google: could not decode service account json %v", err)
		}
		// Required scopes for groups api
		// https://developers.google.com/admin-sdk/directory/v1/reference/groups/list
		conf, err := JWTConfigFromJSON(apiCreds, admin.AdminDirectoryUserReadonlyScope, admin.AdminDirectoryGroupReadonlyScope)
		if err != nil {
			return nil, fmt.Errorf("identity/google: failed making jwt config from json %v", err)
		}
		client := conf.Client(context.TODO())
		gp.apiClient, err = admin.New(client)
		if err != nil {
			return nil, fmt.Errorf("identity/google: failed creating admin service %v", err)
		}
	} else {
		log.Warn().Msg("identity/google: no service account, cannot retrieve groups")
	}

	gp.RevokeURL, err = url.Parse(claims.RevokeURL)
	if err != nil {
		return nil, err
	}

	return gp, nil
}

// Revoke revokes the access token a given session state.
//
// https://developers.google.com/identity/protocols/OAuth2WebServer#tokenrevoke
func (p *GoogleProvider) Revoke(accessToken string) error {
	params := url.Values{}
	params.Add("token", accessToken)
	err := httputil.Client("POST", p.RevokeURL.String(), version.UserAgent(), nil, params, nil)
	if err != nil && err != httputil.ErrTokenRevoked {
		return err
	}
	return nil
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
func (p *GoogleProvider) GetSignInURL(state string) string {
	return p.oauth.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.SetAuthURLParam("prompt", "select_account consent"))
}

// Authenticate creates an identity session with google from a authorization code, and follows up
// call to the admin/group api to check what groups the user is in.
func (p *GoogleProvider) Authenticate(ctx context.Context, code string) (*sessions.SessionState, error) {
	// convert authorization code into a token
	oauth2Token, err := p.oauth.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("identity/google: token exchange failed %v", err)
	}

	// id_token is a JWT that contains identity information about the user
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("identity/google: response did not contain an id_token")
	}
	session, err := p.IDTokenToSession(ctx, rawIDToken)
	if err != nil {
		return nil, err
	}
	session.AccessToken = oauth2Token.AccessToken
	session.RefreshToken = oauth2Token.RefreshToken
	return session, nil
}

// Refresh renews a user's session using an oidc refresh token withoutreprompting the user.
// Group membership is also refreshed.
// https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokens
func (p *GoogleProvider) Refresh(ctx context.Context, s *sessions.SessionState) (*sessions.SessionState, error) {
	if s.RefreshToken == "" {
		return nil, errors.New("identity: missing refresh token")
	}
	t := oauth2.Token{RefreshToken: s.RefreshToken}
	newToken, err := p.oauth.TokenSource(ctx, &t).Token()
	if err != nil {
		log.Error().Err(err).Msg("identity: refresh failed")
		return nil, err
	}
	// id_token contains claims about the authenticated user
	rawIDToken, ok := newToken.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("identity/google: response did not contain an id_token")
	}
	newSession, err := p.IDTokenToSession(ctx, rawIDToken)
	if err != nil {
		return nil, err
	}
	newSession.AccessToken = newToken.AccessToken
	newSession.RefreshToken = s.RefreshToken
	return newSession, nil
}

// IDTokenToSession takes an identity provider issued JWT as input ('id_token')
// and returns a session state. The provided token's audience ('aud') must
// match Pomerium's client_id.
func (p *GoogleProvider) IDTokenToSession(ctx context.Context, rawIDToken string) (*sessions.SessionState, error) {
	idToken, err := p.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("identity/google: could not verify id_token %v", err)
	}
	var claims struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	}
	// parse claims from the raw, encoded jwt token
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("identity/google: failed to parse id_token claims %v", err)
	}

	// google requires additional call to retrieve groups.
	groups, err := p.UserGroups(ctx, claims.Email)
	if err != nil {
		return nil, fmt.Errorf("identity/google: could not retrieve groups %v", err)
	}

	return &sessions.SessionState{
		IDToken:         rawIDToken,
		RefreshDeadline: idToken.Expiry.Truncate(time.Second),
		Email:           claims.Email,
		User:            idToken.Subject,
		Groups:          groups,
	}, nil
}

// UserGroups returns a slice of group names a given user is in
// NOTE: groups via Directory API is limited to 1 QPS!
// https://developers.google.com/admin-sdk/directory/v1/reference/groups/list
// https://developers.google.com/admin-sdk/directory/v1/limits
func (p *GoogleProvider) UserGroups(ctx context.Context, user string) ([]string, error) {
	var groups []string
	if p.apiClient != nil {
		req := p.apiClient.Groups.List().UserKey(user).MaxResults(100)
		resp, err := req.Do()
		if err != nil {
			return nil, fmt.Errorf("identity/google: group api request failed %v", err)
		}
		for _, group := range resp.Groups {
			groups = append(groups, group.Email)
		}
	}
	return groups, nil
}

// JWTConfigFromJSON uses a Google Developers service account JSON key file to read
// the credentials that authorize and authenticate the requests.
// Create a service account on "Credentials" for your project at
// https://console.developers.google.com to download a JSON key file.
func JWTConfigFromJSON(jsonKey []byte, scope ...string) (*jwt.Config, error) {
	var f credentialsFile
	if err := json.Unmarshal(jsonKey, &f); err != nil {
		return nil, err
	}
	if f.Type != "service_account" {
		return nil, fmt.Errorf("identity/google: 'type' field is %q (expected %q)", f.Type, "service_account")
	}
	// Service account must impersonate a user : https://stackoverflow.com/a/48601364
	if f.ImpersonateUser == "" {
		return nil, errors.New("identity/google: impersonate_user not found in json config")
	}
	scope = append([]string(nil), scope...) // copy
	return f.jwtConfig(scope), nil
}

// credentialsFile is the unmarshalled representation of a credentials file.
type credentialsFile struct {
	Type string `json:"type"` // serviceAccountKey or userCredentialsKey

	// Service account must impersonate a user
	ImpersonateUser string `json:"impersonate_user"`
	// Service Account fields
	ClientEmail  string `json:"client_email"`
	PrivateKeyID string `json:"private_key_id"`
	PrivateKey   string `json:"private_key"`
	TokenURL     string `json:"token_uri"`
	ProjectID    string `json:"project_id"`

	// User Credential fields
	ClientSecret string `json:"client_secret"`
	ClientID     string `json:"client_id"`
	RefreshToken string `json:"refresh_token"`
}

func (f *credentialsFile) jwtConfig(scopes []string) *jwt.Config {
	cfg := &jwt.Config{
		Subject:      f.ImpersonateUser,
		Email:        f.ClientEmail,
		PrivateKey:   []byte(f.PrivateKey),
		PrivateKeyID: f.PrivateKeyID,
		Scopes:       scopes,
		TokenURL:     f.TokenURL,
	}
	if cfg.TokenURL == "" {
		cfg.TokenURL = JWTTokenURL
	}
	return cfg
}
