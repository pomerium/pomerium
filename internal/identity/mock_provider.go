package identity

import (
	"context"
	"net/url"

	"golang.org/x/oauth2"

	"github.com/pomerium/pomerium/internal/sessions"
)

// MockProvider provides a mocked implementation of the providers interface.
type MockProvider struct {
	AuthenticateResponse sessions.State
	AuthenticateError    error
	RefreshResponse      sessions.State
	RefreshError         error
	RevokeError          error
	GetSignInURLResponse string
	LogOutResponse       url.URL
	LogOutError          error
}

// Authenticate is a mocked providers function.
func (mp MockProvider) Authenticate(ctx context.Context, code string) (*sessions.State, error) {
	return &mp.AuthenticateResponse, mp.AuthenticateError
}

// Refresh is a mocked providers function.
func (mp MockProvider) Refresh(ctx context.Context, s *sessions.State) (*sessions.State, error) {
	return &mp.RefreshResponse, mp.RefreshError
}

// Revoke is a mocked providers function.
func (mp MockProvider) Revoke(ctx context.Context, s *oauth2.Token) error {
	return mp.RevokeError
}

// GetSignInURL is a mocked providers function.
func (mp MockProvider) GetSignInURL(s string) string { return mp.GetSignInURLResponse }

// LogOut is a mocked providers function.
func (mp MockProvider) LogOut() (*url.URL, error) { return &mp.LogOutResponse, mp.LogOutError }
