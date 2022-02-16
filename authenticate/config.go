package authenticate

import (
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/identity"
)

type authenticateConfig struct {
	getIdentityProvider func(options *config.Options, idpID string) (identity.Authenticator, error)
}

// An Option customizes the Authenticate config.
type Option func(*authenticateConfig)

func getAuthenticateConfig(options ...Option) *authenticateConfig {
	cfg := new(authenticateConfig)
	WithGetIdentityProvider(defaultGetIdentityProvider)(cfg)
	for _, option := range options {
		option(cfg)
	}
	return cfg
}

// WithGetIdentityProvider sets the getIdentityProvider function in the config.
func WithGetIdentityProvider(getIdentityProvider func(options *config.Options, idpID string) (identity.Authenticator, error)) Option {
	return func(cfg *authenticateConfig) {
		cfg.getIdentityProvider = getIdentityProvider
	}
}
