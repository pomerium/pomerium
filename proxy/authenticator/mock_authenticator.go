package authenticator // import "github.com/pomerium/pomerium/proxy/authenticator"

import (
	"context"

	"github.com/pomerium/pomerium/internal/sessions"
)

// MockAuthenticate provides a mocked implementation of the authenticator interface.
type MockAuthenticate struct {
	RedeemError      error
	RedeemResponse   *sessions.SessionState
	RefreshResponse  *sessions.SessionState
	RefreshError     error
	ValidateResponse bool
	ValidateError    error
	CloseError       error
}

// Redeem is a mocked authenticator client function.
func (a MockAuthenticate) Redeem(ctx context.Context, code string) (*sessions.SessionState, error) {
	return a.RedeemResponse, a.RedeemError
}

// Refresh is a mocked authenticator client function.
func (a MockAuthenticate) Refresh(ctx context.Context, s *sessions.SessionState) (*sessions.SessionState, error) {
	return a.RefreshResponse, a.RefreshError
}

// Validate is a mocked authenticator client function.
func (a MockAuthenticate) Validate(ctx context.Context, idToken string) (bool, error) {
	return a.ValidateResponse, a.ValidateError
}

// Close is a mocked authenticator client function.
func (a MockAuthenticate) Close() error { return a.CloseError }
