package authenticator // import "github.com/pomerium/pomerium/proxy/authenticator"

import (
	"time"
)

// MockAuthenticate provides a mocked implementation of the authenticator interface.
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

// Redeem is a mocked authenticator client function.
func (a MockAuthenticate) Redeem(code string) (*RedeemResponse, error) {
	return a.RedeemResponse, a.RedeemError
}

// Refresh is a mocked authenticator client function.
func (a MockAuthenticate) Refresh(refreshToken string) (string, time.Time, error) {
	return a.RefreshResponse, a.RefreshTime, a.RefreshError
}

// Validate is a mocked authenticator client function.
func (a MockAuthenticate) Validate(idToken string) (bool, error) {
	return a.ValidateResponse, a.ValidateError
}

// Close is a mocked authenticator client function.
func (a MockAuthenticate) Close() error { return a.CloseError }
