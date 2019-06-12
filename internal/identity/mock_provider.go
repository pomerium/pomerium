package identity // import "github.com/pomerium/pomerium/internal/identity"

import (
	"context"

	"github.com/pomerium/pomerium/internal/sessions"
)

// MockProvider provides a mocked implementation of the providers interface.
type MockProvider struct {
	AuthenticateResponse     sessions.SessionState
	AuthenticateError        error
	IDTokenToSessionResponse sessions.SessionState
	IDTokenToSessionError    error
	ValidateResponse         bool
	ValidateError            error
	RefreshResponse          *sessions.SessionState
	RefreshError             error
	RevokeError              error
	GetSignInURLResponse     string
}

// Authenticate is a mocked providers function.
func (mp MockProvider) Authenticate(ctx context.Context, code string) (*sessions.SessionState, error) {
	return &mp.AuthenticateResponse, mp.AuthenticateError
}

// IDTokenToSession is a mocked providers function.
func (mp MockProvider) IDTokenToSession(ctx context.Context, code string) (*sessions.SessionState, error) {
	return &mp.IDTokenToSessionResponse, mp.IDTokenToSessionError
}

// Validate is a mocked providers function.
func (mp MockProvider) Validate(ctx context.Context, s string) (bool, error) {
	return mp.ValidateResponse, mp.ValidateError
}

// Refresh is a mocked providers function.
func (mp MockProvider) Refresh(ctx context.Context, s *sessions.SessionState) (*sessions.SessionState, error) {
	return mp.RefreshResponse, mp.RefreshError
}

// Revoke is a mocked providers function.
func (mp MockProvider) Revoke(s string) error {
	return mp.RevokeError
}

// GetSignInURL is a mocked providers function.
func (mp MockProvider) GetSignInURL(s string) string { return mp.GetSignInURLResponse }
