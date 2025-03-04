// Package authorize is a pomerium service that is responsible for determining
// if a given request should be authorized (AuthZ).
package authorize

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/rs/zerolog"
	oteltrace "go.opentelemetry.io/otel/trace"
	"golang.org/x/sync/errgroup"

	"github.com/pomerium/datasource/pkg/directory"
	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/authorize/internal/store"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/atomicutil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry/metrics"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/storage"
)

// Authorize struct holds
type Authorize struct {
	state             *atomicutil.Value[*authorizeState]
	store             *store.Store
	currentConfig     *atomicutil.Value[*config.Config]
	accessTracker     *AccessTracker
	globalCache       storage.Cache
	groupsCacheWarmer *cacheWarmer

	tracerProvider oteltrace.TracerProvider
	tracer         oteltrace.Tracer
}

// New validates and creates a new Authorize service from a set of config options.
func New(ctx context.Context, cfg *config.Config) (*Authorize, error) {
	tracerProvider := trace.NewTracerProvider(ctx, "Authorize")
	tracer := tracerProvider.Tracer(trace.PomeriumCoreTracer)
	a := &Authorize{
		currentConfig:  atomicutil.NewValue(&config.Config{Options: new(config.Options)}),
		store:          store.New(),
		globalCache:    storage.NewGlobalCache(time.Minute),
		tracerProvider: tracerProvider,
		tracer:         tracer,
	}
	a.accessTracker = NewAccessTracker(a, accessTrackerMaxSize, accessTrackerDebouncePeriod)

	state, err := newAuthorizeStateFromConfig(ctx, tracerProvider, cfg, a.store, nil)
	if err != nil {
		return nil, err
	}
	a.state = atomicutil.NewValue(state)

	a.groupsCacheWarmer = newCacheWarmer(state.dataBrokerClientConnection, a.globalCache, directory.GroupRecordType)
	return a, nil
}

// GetDataBrokerServiceClient returns the current DataBrokerServiceClient.
func (a *Authorize) GetDataBrokerServiceClient() databroker.DataBrokerServiceClient {
	return a.state.Load().dataBrokerClient
}

// Run runs the authorize service.
func (a *Authorize) Run(ctx context.Context) error {
	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(func() error {
		a.accessTracker.Run(ctx)
		return nil
	})
	eg.Go(func() error {
		a.groupsCacheWarmer.Run(ctx)
		return nil
	})
	return eg.Wait()
}

func validateOptions(o *config.Options) error {
	sharedKey, err := o.GetSharedKey()
	if err != nil {
		return fmt.Errorf("authorize: bad 'SHARED_SECRET': %w", err)
	}
	if _, err := cryptutil.NewAEADCipher(sharedKey); err != nil {
		return fmt.Errorf("authorize: bad 'SHARED_SECRET': %w", err)
	}
	return nil
}

// newPolicyEvaluator returns an policy evaluator.
func newPolicyEvaluator(
	ctx context.Context,
	opts *config.Options, store *store.Store, previous *evaluator.Evaluator,
) (*evaluator.Evaluator, error) {
	metrics.AddPolicyCountCallback("pomerium-authorize", func() int64 {
		return int64(opts.NumPolicies())
	})
	ctx = log.WithContext(ctx, func(c zerolog.Context) zerolog.Context {
		return c.Str("service", "authorize")
	})
	ctx, span := trace.Continue(ctx, "authorize.newPolicyEvaluator")
	defer span.End()

	clientCA, err := opts.DownstreamMTLS.GetCA()
	if err != nil {
		return nil, fmt.Errorf("authorize: invalid client CA: %w", err)
	}

	clientCRL, err := opts.DownstreamMTLS.GetCRL()
	if err != nil {
		return nil, fmt.Errorf("authorize: invalid client CRL: %w", err)
	}

	authenticateURL, err := opts.GetInternalAuthenticateURL()
	if err != nil {
		return nil, fmt.Errorf("authorize: invalid authenticate url: %w", err)
	}

	signingKey, err := opts.GetSigningKey()
	if err != nil {
		return nil, fmt.Errorf("authorize: invalid signing key: %w", err)
	}

	// It is important to add an invalid_client_certificate rule even when the
	// mTLS enforcement behavior is set to reject connections at the listener
	// level, because of the per-route TLSDownstreamClientCA setting.
	addDefaultClientCertificateRule := opts.HasAnyDownstreamMTLSClientCA() &&
		opts.DownstreamMTLS.GetEnforcement() != config.MTLSEnforcementPolicy

	clientCertConstraints, err := evaluator.ClientCertConstraintsFromConfig(&opts.DownstreamMTLS)
	if err != nil {
		return nil, fmt.Errorf(
			"authorize: internal error: couldn't build client cert constraints: %w", err)
	}

	allPolicies := slices.Collect(opts.GetAllPolicies())
	return evaluator.New(ctx, store, previous,
		evaluator.WithPolicies(allPolicies),
		evaluator.WithClientCA(clientCA),
		evaluator.WithAddDefaultClientCertificateRule(addDefaultClientCertificateRule),
		evaluator.WithClientCRL(clientCRL),
		evaluator.WithClientCertConstraints(clientCertConstraints),
		evaluator.WithSigningKey(signingKey),
		evaluator.WithAuthenticateURL(authenticateURL.String()),
		evaluator.WithGoogleCloudServerlessAuthenticationServiceAccount(opts.GetGoogleCloudServerlessAuthenticationServiceAccount()),
		evaluator.WithJWTClaimsHeaders(opts.JWTClaimsHeaders),
		evaluator.WithJWTGroupsFilter(opts.JWTGroupsFilter),
		evaluator.WithDefaultJWTIssuerFormat(opts.JWTIssuerFormat),
	)
}

// OnConfigChange updates internal structures based on config.Options
func (a *Authorize) OnConfigChange(ctx context.Context, cfg *config.Config) {
	currentState := a.state.Load()
	a.currentConfig.Store(cfg)
	if newState, err := newAuthorizeStateFromConfig(ctx, a.tracerProvider, cfg, a.store, currentState.evaluator); err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("authorize: error updating state")
	} else {
		a.state.Store(newState)

		if currentState.dataBrokerClientConnection != newState.dataBrokerClientConnection {
			a.groupsCacheWarmer.UpdateConn(newState.dataBrokerClientConnection)
		}
	}
}
