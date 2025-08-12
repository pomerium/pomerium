// Package authenticate is a pomerium service that handles user authentication
// and refersh (AuthN).
package authenticate

import (
	"context"
	"errors"
	"fmt"

	"go.opentelemetry.io/otel/metric"
	oteltrace "go.opentelemetry.io/otel/trace"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/atomicutil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry/metrics"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/telemetry/trace"
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
	backgroundCtx context.Context

	accessTokenVerificationCount          metric.Int64Counter
	accessTokenValidVerificationCount     metric.Int64Counter
	accessTokenInvalidVerificationCount   metric.Int64Counter
	accessTokenVerificationDuration       metric.Int64Histogram
	identityTokenVerificationCount        metric.Int64Counter
	identityTokenValidVerificationCount   metric.Int64Counter
	identityTokenInvalidVerificationCount metric.Int64Counter
	identityTokenVerificationDuration     metric.Int64Histogram

	cfg            *authenticateConfig
	options        *atomicutil.Value[*config.Options]
	state          *atomicutil.Value[*authenticateState]
	tracerProvider oteltrace.TracerProvider
	tracer         oteltrace.Tracer
}

// New validates and creates a new authenticate service from a set of Options.
func New(ctx context.Context, cfg *config.Config, options ...Option) (*Authenticate, error) {
	authenticateConfig := getAuthenticateConfig(options...)

	tracerProvider := trace.NewTracerProvider(ctx, "Authenticate")
	tracer := tracerProvider.Tracer(trace.PomeriumCoreTracer)

	a := &Authenticate{
		backgroundCtx: ctx,

		accessTokenVerificationCount: metrics.Int64Counter("authenticate.idp_access_token.verifications",
			metric.WithDescription("Number of IDP access token verifications."),
			metric.WithUnit("{verification}")),
		accessTokenValidVerificationCount: metrics.Int64Counter("authenticate.idp_access_token.valid_verifications",
			metric.WithDescription("Number of valid IDP access token verifications."),
			metric.WithUnit("{verification}")),
		accessTokenInvalidVerificationCount: metrics.Int64Counter("authenticate.idp_access_token.invalid_verifications",
			metric.WithDescription("Number of invalid IDP access token verifications."),
			metric.WithUnit("{verification}")),
		accessTokenVerificationDuration: metrics.Int64Histogram("authenticate.idp_access_token.verification.duration",
			metric.WithDescription("Duration of access token verification."),
			metric.WithUnit("ms")),
		identityTokenVerificationCount: metrics.Int64Counter("authenticate.idp_identity_token.verifications",
			metric.WithDescription("Number of IDP identity token verifications."),
			metric.WithUnit("{verification}")),
		identityTokenValidVerificationCount: metrics.Int64Counter("authenticate.idp_identity_token.valid_verifications",
			metric.WithDescription("Number of valid IDP identity token verifications."),
			metric.WithUnit("{verification}")),
		identityTokenInvalidVerificationCount: metrics.Int64Counter("authenticate.idp_identity_token.invalid_verifications",
			metric.WithDescription("Number of invalid IDP identity token verifications."),
			metric.WithUnit("{verification}")),
		identityTokenVerificationDuration: metrics.Int64Histogram("authenticate.idp_identity_token.verification.duration",
			metric.WithDescription("Duration of identity token verification."),
			metric.WithUnit("ms")),

		cfg:            authenticateConfig,
		options:        config.NewAtomicOptions(),
		state:          atomicutil.NewValue(newAuthenticateState()),
		tracerProvider: tracerProvider,
		tracer:         tracer,
	}

	a.options.Store(cfg.Options)

	state, err := newAuthenticateStateFromConfig(ctx, tracerProvider, cfg, authenticateConfig)
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
	if state, err := newAuthenticateStateFromConfig(ctx, a.tracerProvider, cfg, a.cfg); err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("authenticate: failed to update state")
	} else {
		a.state.Store(state)
	}
}
