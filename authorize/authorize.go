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
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
)

// Authorize struct holds
type Authorize struct {
	state          *atomicAuthorizeState
	store          *evaluator.Store
	currentOptions *config.AtomicOptions
	templates      *template.Template

	dataBrokerDataLock sync.RWMutex
	dataBrokerData     evaluator.DataBrokerData
}

// New validates and creates a new Authorize service from a set of config options.
func New(cfg *config.Config) (*Authorize, error) {
	a := Authorize{
		currentOptions: config.NewAtomicOptions(),
		store:          evaluator.NewStore(),
		templates:      template.Must(frontend.NewTemplates()),
		dataBrokerData: make(evaluator.DataBrokerData),
	}

	state, err := newAuthorizeStateFromConfig(cfg, a.store)
	if err != nil {
		return nil, err
	}
	a.state = newAtomicAuthorizeState(state)

	return &a, nil
}

func validateOptions(o *config.Options) error {
	if _, err := cryptutil.NewAEADCipherFromBase64(o.SharedKey); err != nil {
		return fmt.Errorf("authorize: bad 'SHARED_SECRET': %w", err)
	}
	if err := urlutil.ValidateURL(o.AuthenticateURL); err != nil {
		return fmt.Errorf("authorize: invalid 'AUTHENTICATE_SERVICE_URL': %w", err)
	}
	if err := urlutil.ValidateURL(o.DataBrokerURL); err != nil {
		return fmt.Errorf("authorize: invalid 'DATABROKER_SERVICE_URL': %w", err)
	}
	return nil
}

// newPolicyEvaluator returns an policy evaluator.
func newPolicyEvaluator(opts *config.Options, store *evaluator.Store) (*evaluator.Evaluator, error) {
	metrics.AddPolicyCountCallback("pomerium-authorize", func() int64 {
		return int64(len(opts.Policies))
	})
	ctx := context.Background()
	_, span := trace.StartSpan(ctx, "authorize.newPolicyEvaluator")
	defer span.End()
	return evaluator.New(opts, store)
}

// OnConfigChange updates internal structures based on config.Options
func (a *Authorize) OnConfigChange(cfg *config.Config) {
	log.Info().Str("checksum", fmt.Sprintf("%x", cfg.Options.Checksum())).Msg("authorize: updating options")
	a.currentOptions.Store(cfg.Options)
	if state, err := newAuthorizeStateFromConfig(cfg, a.store); err != nil {
		log.Error().Err(err).Msg("authorize: error updating state")
	} else {
		a.state.Store(state)
	}
}
