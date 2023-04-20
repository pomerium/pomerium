package authenticate

import (
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/identity"
	identitypb "github.com/pomerium/pomerium/pkg/grpc/identity"
)

type authenticateConfig struct {
	getIdentityProvider func(options *config.Options, idpID string) (identity.Authenticator, error)
	profileTrimFn       func(*identitypb.Profile)
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

// WithProfileTrimFn sets the profileTrimFn function in the config
func WithProfileTrimFn(profileTrimFn func(*identitypb.Profile)) Option {
	return func(cfg *authenticateConfig) {
		cfg.profileTrimFn = profileTrimFn
	}
}
