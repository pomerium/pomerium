// Package authenticate is a pomerium service that handles user authentication
// and refersh (AuthN).
package authenticate

import (
	"context"
	"errors"
	"fmt"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/atomicutil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/cryptutil"
)

// ValidateOptions checks that configuration are complete and valid.
// Returns on first error found.
func ValidateOptions(o *config.Options) error {
	sharedKey, err := o.GetSharedKey()
	if err != nil {
		return fmt.Errorf("authenticate: 'SHARED_SECRET' invalid: %w", err)
	}
	if _, err := cryptutil.NewAEADCipher(sharedKey); err != nil {
		return fmt.Errorf("authenticate: 'SHARED_SECRET' invalid: %w", err)
	}
	cookieSecret, err := o.GetCookieSecret()
	if err != nil {
		return fmt.Errorf("authenticate: 'COOKIE_SECRET' invalid: %w", err)
	}
	if _, err := cryptutil.NewAEADCipher(cookieSecret); err != nil {
		return fmt.Errorf("authenticate: 'COOKIE_SECRET' invalid %w", err)
	}
	if o.AuthenticateCallbackPath == "" {
		return errors.New("authenticate: 'AUTHENTICATE_CALLBACK_PATH' is required")
	}
	return nil
}

// Authenticate contains data required to run the authenticate service.
type Authenticate struct {
	cfg     *authenticateConfig
	options *atomicutil.Value[*config.Options]
	state   *atomicutil.Value[*authenticateState]
}

// New validates and creates a new authenticate service from a set of Options.
func New(ctx context.Context, cfg *config.Config, options ...Option) (*Authenticate, error) {
	authenticateConfig := getAuthenticateConfig(options...)
	a := &Authenticate{
		cfg:     authenticateConfig,
		options: config.NewAtomicOptions(),
		state:   atomicutil.NewValue(newAuthenticateState()),
	}

	a.options.Store(cfg.Options)

	state, err := newAuthenticateStateFromConfig(ctx, cfg, authenticateConfig)
	if err != nil {
		return nil, err
	}
	a.state.Store(state)

	return a, nil
}

// OnConfigChange updates internal structures based on config.Options
func (a *Authenticate) OnConfigChange(ctx context.Context, cfg *config.Config) {
	if a == nil {
		return
	}

	a.options.Store(cfg.Options)
	if state, err := newAuthenticateStateFromConfig(ctx, cfg, a.cfg); err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("authenticate: failed to update state")
	} else {
		a.state.Store(state)
	}
}
