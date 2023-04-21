package identity

import (
	"context"
	"net/url"

	"golang.org/x/oauth2"

	"github.com/pomerium/pomerium/internal/identity/identity"
)

// MockProvider provides a mocked implementation of the providers interface.
type MockProvider struct {
	AuthenticateResponse oauth2.Token
	AuthenticateError    error
	RefreshResponse      oauth2.Token
	RefreshError         error
	RevokeError          error
	GetSignInURLResponse string
	LogOutResponse       url.URL
	LogOutError          error
	UpdateUserInfoError  error
}

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

// GetSignInURL is a mocked providers function.
func (mp MockProvider) GetSignInURL(_ string) (string, error) { return mp.GetSignInURLResponse, nil }

// LogOut is a mocked providers function.
func (mp MockProvider) LogOut() (*url.URL, error) { return &mp.LogOutResponse, mp.LogOutError }

// UpdateUserInfo is a mocked providers function.
func (mp MockProvider) UpdateUserInfo(_ context.Context, _ *oauth2.Token, _ interface{}) error {
	return mp.UpdateUserInfoError
}

// Name returns the provider name.
func (mp MockProvider) Name() string {
	return "mock"
}
