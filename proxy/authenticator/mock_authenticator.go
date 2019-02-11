package authenticator // import "github.com/pomerium/pomerium/proxy/authenticator"

import (
	"time"
)

// MockAuthenticate is a mock authenticator interface
type MockAuthenticate struct {
	RedeemError      error
	RedeemResponse   *RedeemResponse
	RefreshResponse  string
	RefreshTime      time.Time
	RefreshError     error
	ValidateResponse bool
	ValidateError    error
	CloseError       error
}

// Redeem is a mocked implementation for authenticator testing.
func (a MockAuthenticate) Redeem(code string) (*RedeemResponse, error) {
	return a.RedeemResponse, a.RedeemError
}

// Refresh is a mocked implementation for authenticator testing.
func (a MockAuthenticate) Refresh(refreshToken string) (string, time.Time, error) {
	return a.RefreshResponse, a.RefreshTime, a.RefreshError
}

// Validate is a mocked implementation for authenticator testing.
func (a MockAuthenticate) Validate(idToken string) (bool, error) {
	return a.ValidateResponse, a.ValidateError
}

// Close is a mocked implementation for authenticator testing.
func (a MockAuthenticate) Close() error { return a.ValidateError }
