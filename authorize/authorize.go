// Package authorize is a pomerium service that is responsible for determining
// if a given request should be authorized (AuthZ).
package authorize

import (
	"context"
	"fmt"
	"html/template"
	"sync"

	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/frontend"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry/metrics"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
	"github.com/pomerium/pomerium/pkg/cryptutil"
)

// Authorize struct holds
type Authorize struct {
	state          *atomicAuthorizeState
	store          *evaluator.Store
	currentOptions *config.AtomicOptions
	templates      *template.Template

	dataBrokerInitialSync chan struct{}

	// The stateLock prevents updating the evaluator store simultaneously with an evaluation.
	// This should provide a consistent view of the data at a given server/record version and
	// avoid partial updates.
	stateLock sync.RWMutex
}

// New validates and creates a new Authorize service from a set of config options.
func New(cfg *config.Config) (*Authorize, error) {
	a := Authorize{
		currentOptions:        config.NewAtomicOptions(),
		store:                 evaluator.NewStore(),
		templates:             template.Must(frontend.NewTemplates()),
		dataBrokerInitialSync: make(chan struct{}),
	}

	state, err := newAuthorizeStateFromConfig(cfg, a.store)
	if err != nil {
		return nil, err
	}
	a.state = newAtomicAuthorizeState(state)

	return &a, nil
}

// Run runs the authorize service.
func (a *Authorize) Run(ctx context.Context) error {
	return newDataBrokerSyncer(a).Run(ctx)
}

// WaitForInitialSync blocks until the initial sync is complete.
func (a *Authorize) WaitForInitialSync(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-a.dataBrokerInitialSync:
	}
	log.Info(ctx).Msg("initial sync from databroker complete")
	return nil
}

func validateOptions(o *config.Options) error {
	sharedKey, err := o.GetSharedKey()
	if err != nil {
		return fmt.Errorf("authorize: bad 'SHARED_SECRET': %w", err)
	}
	if _, err := cryptutil.NewAEADCipher(sharedKey); err != nil {
		return fmt.Errorf("authorize: bad 'SHARED_SECRET': %w", err)
	}
	if _, err := o.GetAuthenticateURL(); err != nil {
		return fmt.Errorf("authorize: invalid 'AUTHENTICATE_SERVICE_URL': %w", err)
	}
	return nil
}

// newPolicyEvaluator returns an policy evaluator.
func newPolicyEvaluator(opts *config.Options, store *evaluator.Store) (*evaluator.Evaluator, error) {
	metrics.AddPolicyCountCallback("pomerium-authorize", func() int64 {
		return int64(len(opts.GetAllPolicies()))
	})
	ctx := context.Background()
	_, span := trace.StartSpan(ctx, "authorize.newPolicyEvaluator")
	defer span.End()
	return evaluator.New(ctx, store, opts)
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
