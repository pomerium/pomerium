// Package authorize is a pomerium service that is responsible for determining
// if a given request should be authorized (AuthZ).
package authorize // import "github.com/pomerium/pomerium/authorize"

import (
	"context"
	"fmt"

	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/authorize/evaluator/opa"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/cryptutil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry/metrics"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
)

// Authorize struct holds
type Authorize struct {
	pe evaluator.Evaluator
}

// New validates and creates a new Authorize service from a set of config options.
func New(opts config.Options) (*Authorize, error) {
	if err := validateOptions(opts); err != nil {
		return nil, fmt.Errorf("authorize: bad options: %w", err)
	}
	var a Authorize
	var err error
	if a.pe, err = newPolicyEvaluator(&opts); err != nil {
		return nil, err
	}
	return &a, nil
}

func validateOptions(o config.Options) error {
	if _, err := cryptutil.NewAEADCipherFromBase64(o.SharedKey); err != nil {
		return fmt.Errorf("bad shared_secret: %w", err)
	}
	return nil
}

// newPolicyEvaluator returns an policy evaluator.
func newPolicyEvaluator(opts *config.Options) (evaluator.Evaluator, error) {
	metrics.AddPolicyCountCallback("authorize", func() int64 {
		return int64(len(opts.Policies))
	})
	ctx := context.Background()
	ctx, span := trace.StartSpan(ctx, "authorize.newPolicyEvaluator")
	defer span.End()

	data := map[string]interface{}{
		"shared_key":     opts.SharedKey,
		"route_policies": opts.Policies,
		"admins":         opts.Administrators,
	}
	return opa.New(ctx, &opa.Options{Data: data})
}

// UpdateOptions implements the OptionsUpdater interface and updates internal
// structures based on config.Options
func (a *Authorize) UpdateOptions(opts config.Options) error {
	log.Info().Str("checksum", fmt.Sprintf("%x", opts.Checksum())).Msg("authorize: updating options")
	var err error
	if a.pe, err = newPolicyEvaluator(&opts); err != nil {
		return err
	}
	return nil
}
