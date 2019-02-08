package providers // import "github.com/pomerium/pomerium/internal/providers"

import (
	"context"
	"net/url"
	"time"

	oidc "github.com/pomerium/go-oidc"
	"golang.org/x/oauth2"

	"github.com/pomerium/pomerium/authenticate/circuit"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/version"
)

// defaultAzureProviderURL Users with both a personal Microsoft
// account and a work or school account from Azure Active Directory (Azure AD)
// an sign in to the application.
const defaultAzureProviderURL = "https://login.microsoftonline.com/common"

// AzureProvider is an implementation of the Provider interface
type AzureProvider struct {
	*IdentityProvider
	cb *circuit.Breaker
	// non-standard oidc fields
	RevokeURL *url.URL
}

// NewAzureProvider returns a new AzureProvider and sets the provider url endpoints.
// If non-"common" tenant is desired, ProviderURL must be set.
// https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-protocols-oidc
func NewAzureProvider(p *IdentityProvider) (*AzureProvider, error) {
	ctx := context.Background()

	if p.ProviderURL == "" {
		p.ProviderURL = defaultAzureProviderURL
	}
	log.Info().Msgf("provider url %s", p.ProviderURL)
	var err error
	p.provider, err = oidc.NewProvider(ctx, p.ProviderURL)
	if err != nil {
		return nil, err
	}
	if len(p.Scopes) == 0 {
		p.Scopes = []string{oidc.ScopeOpenID, "profile", "email", "offline_access"}
	}
	p.verifier = p.provider.Verifier(&oidc.Config{ClientID: p.ClientID})
	p.oauth = &oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: p.ClientSecret,
		Endpoint:     p.provider.Endpoint(),
		RedirectURL:  p.RedirectURL.String(),
		Scopes:       p.Scopes,
	}

	azureProvider := &AzureProvider{
		IdentityProvider: p,
	}
	// azure has a "end session endpoint"
	var claims struct {
		RevokeURL string `json:"end_session_endpoint"`
	}

	if err := p.provider.Claims(&claims); err != nil {
		return nil, err
	}

	azureProvider.RevokeURL, err = url.Parse(claims.RevokeURL)
	if err != nil {
		return nil, err
	}

	azureProvider.cb = circuit.NewBreaker(&circuit.Options{
		HalfOpenConcurrentRequests: 2,
		OnStateChange:              azureProvider.cbStateChange,
		OnBackoff:                  azureProvider.cbBackoff,
		ShouldTripFunc:             func(c circuit.Counts) bool { return c.ConsecutiveFailures >= 3 },
		ShouldResetFunc:            func(c circuit.Counts) bool { return c.ConsecutiveSuccesses >= 6 },
		BackoffDurationFunc: circuit.ExponentialBackoffDuration(
			time.Duration(200)*time.Second,
			time.Duration(500)*time.Millisecond),
	})

	return azureProvider, nil
}

func (p *AzureProvider) cbBackoff(duration time.Duration, reset time.Time) {
	log.Info().Dur("duration", duration).Msg("authenticate/providers/azure.cbBackoff")

}

func (p *AzureProvider) cbStateChange(from, to circuit.State) {
	log.Info().Str("from", from.String()).Str("to", to.String()).Msg("authenticate/providers/azure.cbStateChange")
}

// Revoke revokes the access token a given session state.
//https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-protocols-oidc#send-a-sign-out-request
func (p *AzureProvider) Revoke(token string) error {
	params := url.Values{}
	params.Add("token", token)
	err := httputil.Client("POST", p.RevokeURL.String(), version.UserAgent(), params, nil)
	if err != nil && err != httputil.ErrTokenRevoked {
		return err
	}
	return nil
}

// GetSignInURL returns the sign in url with typical oauth parameters
func (p *AzureProvider) GetSignInURL(state string) string {
	return p.oauth.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.ApprovalForce)
}
