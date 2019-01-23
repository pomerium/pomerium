package providers // import "github.com/pomerium/pomerium/internal/providers"

import (
	"context"
	"time"

	oidc "github.com/pomerium/go-oidc"
	"golang.org/x/oauth2"

	"github.com/pomerium/pomerium/authenticate/circuit"
	"github.com/pomerium/pomerium/internal/log"
)

const defaultGitlabProviderURL = "https://gitlab.com"

// GitlabProvider is an implementation of the Provider interface.
type GitlabProvider struct {
	*ProviderData
	cb *circuit.Breaker
}

// NewGitlabProvider returns a new Gitlab identity provider; defaults to the hosted version.
//
// Unlike other providers, `email` is not returned from the initial OIDC token. To retrieve email,
// a secondary call must be made to the user's info endpoint. Unfortunately, email is not guaranteed
// or even likely to be returned even if the user has it set as their email must be set to public.
// As pomerium is currently very email centric, I would caution using until Gitlab fixes the issue.
//
// See :
// - https://gitlab.com/gitlab-org/gitlab-ce/issues/44435#note_88150387
// - https://docs.gitlab.com/ee/integration/openid_connect_provider.html
// - https://docs.gitlab.com/ee/integration/oauth_provider.html
// - https://docs.gitlab.com/ee/api/oauth2.html
// - https://gitlab.com/.well-known/openid-configuration
func NewGitlabProvider(p *ProviderData) (*GitlabProvider, error) {
	ctx := context.Background()
	if p.ProviderURL == "" {
		p.ProviderURL = defaultGitlabProviderURL
	}
	var err error
	p.provider, err = oidc.NewProvider(ctx, p.ProviderURL)
	if err != nil {
		return nil, err
	}
	p.Scopes = []string{oidc.ScopeOpenID, "read_user"}

	p.verifier = p.provider.Verifier(&oidc.Config{ClientID: p.ClientID})
	p.oauth = &oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: p.ClientSecret,
		Endpoint:     p.provider.Endpoint(),
		RedirectURL:  p.RedirectURL.String(),
		Scopes:       p.Scopes,
	}
	gitlabProvider := &GitlabProvider{
		ProviderData: p,
	}
	gitlabProvider.cb = circuit.NewBreaker(&circuit.Options{
		HalfOpenConcurrentRequests: 2,
		OnStateChange:              gitlabProvider.cbStateChange,
		OnBackoff:                  gitlabProvider.cbBackoff,
		ShouldTripFunc:             func(c circuit.Counts) bool { return c.ConsecutiveFailures >= 3 },
		ShouldResetFunc:            func(c circuit.Counts) bool { return c.ConsecutiveSuccesses >= 6 },
		BackoffDurationFunc: circuit.ExponentialBackoffDuration(
			time.Duration(200)*time.Second,
			time.Duration(500)*time.Millisecond),
	})

	return gitlabProvider, nil
}

func (p *GitlabProvider) cbBackoff(duration time.Duration, reset time.Time) {
	log.Info().Dur("duration", duration).Msg("authenticate/providers/gitlab.cbBackoff")

}

func (p *GitlabProvider) cbStateChange(from, to circuit.State) {
	log.Info().Str("from", from.String()).Str("to", to.String()).Msg("authenticate/providers/gitlab.cbStateChange")
}
