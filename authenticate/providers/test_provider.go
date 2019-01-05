package providers // import "github.com/pomerium/pomerium/internal/providers"

import (
	"net/url"
	"time"

	"github.com/pomerium/pomerium/internal/sessions"
)

// TestProvider is a test implementation of the Provider interface.
type TestProvider struct {
	*ProviderData

	ValidToken   bool
	ValidGroup   bool
	SignInURL    string
	Refresh      bool
	RefreshFunc  func(string) (string, time.Duration, error)
	RefreshError error
	Session      *sessions.SessionState
	RedeemError  error
	RevokeError  error
	Groups       []string
	GroupsError  error
	GroupsCall   int
}

// NewTestProvider creates a new mock test provider.
func NewTestProvider(providerURL *url.URL) *TestProvider {
	host := &url.URL{
		Scheme: "http",
		Host:   providerURL.Host,
		Path:   "/authorize",
	}
	return &TestProvider{
		ProviderData: &ProviderData{
			ProviderName: "Test Provider",
			ProviderURL:  host.String(),
		},
	}
}

// ValidateSessionState returns the mock provider's ValidToken field value.
func (tp *TestProvider) ValidateSessionState(*sessions.SessionState) bool {
	return tp.ValidToken
}

// GetSignInURL returns the mock provider's SignInURL field value.
func (tp *TestProvider) GetSignInURL(finalRedirect string) string {
	return tp.SignInURL
}

// RefreshSessionIfNeeded returns the mock provider's Refresh value, or an error.
func (tp *TestProvider) RefreshSessionIfNeeded(*sessions.SessionState) (bool, error) {
	return tp.Refresh, tp.RefreshError
}

// RefreshAccessToken returns the mock provider's refresh access token information
func (tp *TestProvider) RefreshAccessToken(s string) (string, time.Duration, error) {
	return tp.RefreshFunc(s)
}

// Revoke returns nil
func (tp *TestProvider) Revoke(*sessions.SessionState) error {
	return tp.RevokeError
}

// ValidateGroupMembership returns the mock provider's GroupsError if not nil, or the Groups field value.
func (tp *TestProvider) ValidateGroupMembership(string, []string) ([]string, error) {
	return tp.Groups, tp.GroupsError
}

// Redeem returns the mock provider's Session and RedeemError field value.
func (tp *TestProvider) Redeem(code string) (*sessions.SessionState, error) {
	return tp.Session, tp.RedeemError

}

// Stop fulfills the Provider interface
func (tp *TestProvider) Stop() {
	return
}
