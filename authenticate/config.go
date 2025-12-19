package authenticate

import (
	"context"

	oteltrace "go.opentelemetry.io/otel/trace"

	"github.com/pomerium/pomerium/authenticate/events"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/authenticateflow"
	identitypb "github.com/pomerium/pomerium/pkg/grpc/identity"
	"github.com/pomerium/pomerium/pkg/identity"
)

type authenticateConfig struct {
	getIdentityProvider func(ctx context.Context, tracerProvider oteltrace.TracerProvider, options *config.Options, idpID string) (identity.Authenticator, error)
	profileTrimFn       func(*identitypb.Profile)
	authEventFn         events.AuthEventFn

	sshSignHandler authenticateflow.SSHSignInHandler
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

func WithSSHSignInHandler(handler authenticateflow.SSHSignInHandler) Option {
	return func(ac *authenticateConfig) {
		ac.sshSignHandler = handler
	}
}

// WithGetIdentityProvider sets the getIdentityProvider function in the config.
func WithGetIdentityProvider(getIdentityProvider func(ctx context.Context, tracerProvider oteltrace.TracerProvider, options *config.Options, idpID string) (identity.Authenticator, error)) Option {
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

// WithOnAuthenticationEventHook sets the authEventFn function in the config
func WithOnAuthenticationEventHook(fn events.AuthEventFn) Option {
	return func(cfg *authenticateConfig) {
		cfg.authEventFn = fn
	}
}
