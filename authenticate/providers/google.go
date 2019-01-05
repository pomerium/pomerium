package providers // import "github.com/pomerium/pomerium/internal/providers"

import (
	"context"
	"net/url"
	"time"

	oidc "github.com/pomerium/go-oidc"
	"github.com/pomerium/pomerium/authenticate/circuit"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/version"
	"golang.org/x/oauth2"
)

const defaultGoogleProviderURL = "https://accounts.google.com"

// GoogleProvider is an implementation of the Provider interface.
type GoogleProvider struct {
	*ProviderData
	cb *circuit.Breaker
	// non-standard oidc fields
	RevokeURL *url.URL
}

// NewGoogleProvider returns a new GoogleProvider and sets the provider url endpoints.
func NewGoogleProvider(p *ProviderData) (*GoogleProvider, error) {
	ctx := context.Background()

	if p.ProviderURL == "" {
		p.ProviderURL = defaultGoogleProviderURL
	}
	provider, err := oidc.NewProvider(ctx, p.ProviderURL)
	if err != nil {
		return nil, err
	}

	p.verifier = provider.Verifier(&oidc.Config{ClientID: p.ClientID})
	p.oauth = &oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: p.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  p.RedirectURL.String(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	googleProvider := &GoogleProvider{
		ProviderData: p,
	}
	// google supports a revokation endpoint
	var claims struct {
		RevokeURL string `json:"revocation_endpoint"`
	}

	if err := provider.Claims(&claims); err != nil {
		return nil, err
	}

	googleProvider.RevokeURL, err = url.Parse(claims.RevokeURL)
	if err != nil {
		return nil, err
	}

	googleProvider.cb = circuit.NewBreaker(&circuit.Options{
		HalfOpenConcurrentRequests: 2,
		OnStateChange:              googleProvider.cbStateChange,
		OnBackoff:                  googleProvider.cbBackoff,
		ShouldTripFunc:             func(c circuit.Counts) bool { return c.ConsecutiveFailures >= 3 },
		ShouldResetFunc:            func(c circuit.Counts) bool { return c.ConsecutiveSuccesses >= 6 },
		BackoffDurationFunc: circuit.ExponentialBackoffDuration(
			time.Duration(200)*time.Second,
			time.Duration(500)*time.Millisecond),
	})

	return googleProvider, nil
}

func (p *GoogleProvider) cbBackoff(duration time.Duration, reset time.Time) {
	log.Info().Dur("duration", duration).Msg("authenticate/providers/google.cbBackoff")

}

func (p *GoogleProvider) cbStateChange(from, to circuit.State) {
	log.Info().Str("from", from.String()).Str("to", to.String()).Msg("authenticate/providers/google.cbStateChange")
}

// Revoke revokes the access token a given session state.
//
// https://developers.google.com/identity/protocols/OAuth2WebServer#tokenrevoke
// https://github.com/googleapis/google-api-dotnet-client/issues/1285
func (p *GoogleProvider) Revoke(s *sessions.SessionState) error {
	params := url.Values{}
	params.Add("token", s.AccessToken)
	err := httputil.Client("POST", p.RevokeURL.String(), version.UserAgent(), params, nil)
	if err != nil && err != httputil.ErrTokenRevoked {
		return err
	}
	return nil
}

// GetSignInURL returns the sign in url with typical oauth parameters
// Google requires access type offline
func (p *GoogleProvider) GetSignInURL(state string) string {
	return p.oauth.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.ApprovalForce)
}
