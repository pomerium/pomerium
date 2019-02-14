package providers // import "github.com/pomerium/pomerium/internal/providers"

import (
	"github.com/pomerium/pomerium/internal/sessions" // type Provider interface {
	"golang.org/x/oauth2"
)

// MockProvider provides a mocked implementation of the providers interface.
type MockProvider struct {
	AuthenticateResponse sessions.SessionState
	AuthenticateError    error
	ValidateResponse     bool
	ValidateError        error
	RefreshResponse      *oauth2.Token
	RefreshError         error
	RevokeError          error
	GetSignInURLResponse string
}

// Authenticate is a mocked providers function.
func (mp MockProvider) Authenticate(code string) (*sessions.SessionState, error) {
	return &mp.AuthenticateResponse, mp.AuthenticateError
}

// Validate is a mocked providers function.
func (mp MockProvider) Validate(s string) (bool, error) {
	return mp.ValidateResponse, mp.ValidateError
}

// Refresh is a mocked providers function.
func (mp MockProvider) Refresh(s string) (*oauth2.Token, error) {
	return mp.RefreshResponse, mp.RefreshError
}

// Revoke is a mocked providers function.
func (mp MockProvider) Revoke(s string) error {
	return mp.RevokeError
}

// GetSignInURL is a mocked providers function.
func (mp MockProvider) GetSignInURL(s string) string { return mp.GetSignInURLResponse }
