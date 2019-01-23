package providers // import "github.com/pomerium/pomerium/internal/providers"

import (
	"context"

	oidc "github.com/pomerium/go-oidc"
	"golang.org/x/oauth2"
)

const defaultGitlabProviderURL = "https://gitlab.com"

// GitlabProvider is an implementation of the Provider interface
type GitlabProvider struct {
	*ProviderData
}

// NewGitlabProvider creates a new instance of a Gitlab provider.
func NewGitlabProvider(p *ProviderData) (*GitlabProvider, error) {
	ctx := context.Background()
	if p.ProviderURL == "" {
		p.ProviderURL = defaultGitlabProviderURL
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
		Scopes:       []string{oidc.ScopeOpenID, "read_user"},
	}
	return &GitlabProvider{ProviderData: p}, nil
}
