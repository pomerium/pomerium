package identity

import (
	"context"
	"net/http"

	"golang.org/x/oauth2"

	"github.com/pomerium/pomerium/pkg/identity/identity"
)

// MockProvider provides a mocked implementation of the providers interface.
type MockProvider struct {
	AuthenticateResponse      oauth2.Token
	AuthenticateError         error
	RefreshResponse           oauth2.Token
	RefreshError              error
	RevokeError               error
	UpdateUserInfoError       error
	SignInError               error
	SignOutError              error
	DeviceAuthResponse        oauth2.DeviceAuthResponse
	DeviceAuthError           error
	DeviceAccessTokenResponse oauth2.Token
	DeviceAccessTokenError    error
}

var _ Authenticator = MockProvider{}

// Authenticate is a mocked providers function.
func (mp MockProvider) Authenticate(context.Context, string, identity.State) (*oauth2.Token, error) {
	return &mp.AuthenticateResponse, mp.AuthenticateError
}

// Refresh is a mocked providers function.
func (mp MockProvider) Refresh(context.Context, *oauth2.Token, identity.State) (*oauth2.Token, error) {
	return &mp.RefreshResponse, mp.RefreshError
}

// Revoke is a mocked providers function.
func (mp MockProvider) Revoke(_ context.Context, _ *oauth2.Token) error {
	return mp.RevokeError
}

// UpdateUserInfo is a mocked providers function.
func (mp MockProvider) UpdateUserInfo(_ context.Context, _ *oauth2.Token, _ any) error {
	return mp.UpdateUserInfoError
}

// Name returns the provider name.
func (mp MockProvider) Name() string {
	return "mock"
}

// SignOut is a mocked providers function.
func (mp MockProvider) SignOut(_ http.ResponseWriter, _ *http.Request, _, _, _ string) error {
	return mp.SignOutError
}

// SignIn is a mocked providers function.
func (mp MockProvider) SignIn(_ http.ResponseWriter, _ *http.Request, _ string) error {
	return mp.SignInError
}

// DeviceAccessToken implements Authenticator.
func (mp MockProvider) DeviceAccessToken(ctx context.Context, r *oauth2.DeviceAuthResponse, state identity.State) (*oauth2.Token, error) {
	return &mp.DeviceAccessTokenResponse, mp.DeviceAccessTokenError
}

// DeviceAuth implements Authenticator.
func (mp MockProvider) DeviceAuth(_ context.Context) (*oauth2.DeviceAuthResponse, error) {
	return &mp.DeviceAuthResponse, mp.DeviceAuthError
}
