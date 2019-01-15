package providers // import "github.com/pomerium/pomerium/internal/providers"

import (
	"errors"
	"fmt"
	"time"

	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/singleflight"
)

var (
	_ Provider = &SingleFlightProvider{}
)

// ErrUnexpectedReturnType is an error for an unexpected return type
var (
	ErrUnexpectedReturnType = errors.New("received unexpected return type from single flight func call")
)

// SingleFlightProvider middleware provider that multiple requests for the same object
// to be processed as a single request. This is often called request collapsing or coalesce.
// This middleware leverages the golang singlelflight provider, with modifications for metrics.
//
// It's common among HTTP reverse proxy cache servers such as nginx, Squid or Varnish - they all call it something else but works similarly.
//
// * https://www.varnish-cache.org/docs/3.0/tutorial/handling_misbehaving_servers.html
// * http://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_cache_lock
// * http://wiki.squid-cache.org/Features/CollapsedForwarding
type SingleFlightProvider struct {
	provider Provider

	single *singleflight.Group
}

// NewSingleFlightProvider returns a new SingleFlightProvider
func NewSingleFlightProvider(provider Provider) *SingleFlightProvider {
	return &SingleFlightProvider{
		provider: provider,
		single:   &singleflight.Group{},
	}
}

func (p *SingleFlightProvider) do(endpoint, key string, fn func() (interface{}, error)) (interface{}, error) {
	compositeKey := fmt.Sprintf("%s/%s", endpoint, key)
	resp, _, err := p.single.Do(compositeKey, fn)
	return resp, err
}

// Data returns the provider data
func (p *SingleFlightProvider) Data() *ProviderData {
	return p.provider.Data()
}

// Redeem wraps the provider's Redeem function.
func (p *SingleFlightProvider) Redeem(code string) (*sessions.SessionState, error) {
	return p.provider.Redeem(code)
}

// ValidateSessionState wraps the provider's ValidateSessionState in a single flight call.
func (p *SingleFlightProvider) ValidateSessionState(s *sessions.SessionState) bool {
	response, err := p.do("ValidateSessionState", s.AccessToken, func() (interface{}, error) {
		valid := p.provider.ValidateSessionState(s)
		return valid, nil
	})
	if err != nil {
		return false
	}

	valid, ok := response.(bool)
	if !ok {
		return false
	}

	return valid
}

// GetSignInURL calls the provider's GetSignInURL function.
func (p *SingleFlightProvider) GetSignInURL(finalRedirect string) string {
	return p.provider.GetSignInURL(finalRedirect)
}

// RefreshSessionIfNeeded wraps the provider's RefreshSessionIfNeeded function in a single flight
// call.
func (p *SingleFlightProvider) RefreshSessionIfNeeded(s *sessions.SessionState) (bool, error) {
	response, err := p.do("RefreshSessionIfNeeded", s.RefreshToken, func() (interface{}, error) {
		return p.provider.RefreshSessionIfNeeded(s)
	})
	if err != nil {
		return false, err
	}

	r, ok := response.(bool)
	if !ok {
		return false, ErrUnexpectedReturnType
	}

	return r, nil
}

// Revoke wraps the provider's Revoke function in a single flight call.
func (p *SingleFlightProvider) Revoke(s *sessions.SessionState) error {
	_, err := p.do("Revoke", s.AccessToken, func() (interface{}, error) {
		err := p.provider.Revoke(s)
		return nil, err
	})
	return err
}

// RefreshAccessToken wraps the provider's RefreshAccessToken function in a single flight call.
func (p *SingleFlightProvider) RefreshAccessToken(refreshToken string) (string, time.Duration, error) {
	type Response struct {
		AccessToken string
		ExpiresIn   time.Duration
	}
	response, err := p.do("RefreshAccessToken", refreshToken, func() (interface{}, error) {
		accessToken, expiresIn, err := p.provider.RefreshAccessToken(refreshToken)
		if err != nil {
			return nil, err
		}

		return &Response{
			AccessToken: accessToken,
			ExpiresIn:   expiresIn,
		}, nil
	})
	if err != nil {
		return "", 0, err
	}

	r, ok := response.(*Response)
	if !ok {
		return "", 0, ErrUnexpectedReturnType
	}

	return r.AccessToken, r.ExpiresIn, nil
}

// // Stop calls the provider's stop function
// func (p *SingleFlightProvider) Stop() {
// 	p.provider.Stop()
// }
