// Package authorize is a pomerium service that is responsible for determining
// if a given request should be authorized (AuthZ).
package authorize

import (
	"context"
	"fmt"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/authorize/internal/store"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/atomicutil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry/metrics"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/grpc"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/storage"
)

// Authorize struct holds
type Authorize struct {
	state          *atomicutil.Value[*authorizeState]
	store          *store.Store
	currentOptions *atomicutil.Value[*config.Options]
	accessTracker  *AccessTracker
	globalCache    storage.Cache

	// The stateLock prevents updating the evaluator store simultaneously with an evaluation.
	// This should provide a consistent view of the data at a given server/record version and
	// avoid partial updates.
	stateLock sync.RWMutex
}

// New validates and creates a new Authorize service from a set of config options.
func New(cfg *config.Config) (*Authorize, error) {
	a := &Authorize{
		currentOptions: config.NewAtomicOptions(),
		store:          store.New(),
		globalCache:    storage.NewGlobalCache(time.Minute),
	}
	a.accessTracker = NewAccessTracker(a, accessTrackerMaxSize, accessTrackerDebouncePeriod)

	state, err := newAuthorizeStateFromConfig(cfg, a.store)
	if err != nil {
		return nil, err
	}
	a.state = atomicutil.NewValue(state)

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
		_ = grpc.WaitForReady(ctx, a.state.Load().dataBrokerClientConnection, time.Second*10)
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
func newPolicyEvaluator(opts *config.Options, store *store.Store) (*evaluator.Evaluator, error) {
	metrics.AddPolicyCountCallback("pomerium-authorize", func() int64 {
		return int64(len(opts.GetAllPolicies()))
	})
	ctx := context.Background()
	_, span := trace.StartSpan(ctx, "authorize.newPolicyEvaluator")
	defer span.End()

	clientCA, err := opts.GetClientCA()
	if err != nil {
		return nil, fmt.Errorf("authorize: invalid client CA: %w", err)
	}

	authenticateURL, err := opts.GetInternalAuthenticateURL()
	if err != nil {
		return nil, fmt.Errorf("authorize: invalid authenticate url: %w", err)
	}

	signingKey, err := opts.GetSigningKey()
	if err != nil {
		return nil, fmt.Errorf("authorize: invalid signing key: %w", err)
	}

	return evaluator.New(ctx, store,
		evaluator.WithPolicies(opts.GetAllPolicies()),
		evaluator.WithClientCA(clientCA),
		evaluator.WithSigningKey(signingKey),
		evaluator.WithAuthenticateURL(authenticateURL.String()),
		evaluator.WithGoogleCloudServerlessAuthenticationServiceAccount(opts.GetGoogleCloudServerlessAuthenticationServiceAccount()),
		evaluator.WithJWTClaimsHeaders(opts.JWTClaimsHeaders),
	)
}

// OnConfigChange updates internal structures based on config.Options
func (a *Authorize) OnConfigChange(ctx context.Context, cfg *config.Config) {
	a.currentOptions.Store(cfg.Options)
	if state, err := newAuthorizeStateFromConfig(cfg, a.store); err != nil {
		log.Error(ctx).Err(err).Msg("authorize: error updating state")
	} else {
		a.state.Store(state)
	}
}
