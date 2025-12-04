package databroker

import (
	"context"

	"github.com/rs/zerolog"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry"
)

type ReconcilerRunner interface {
	Run(context.Context) error
	TriggerSync()
}

type reconcilerRunner struct {
	reconciler Reconciler
	trigger    chan struct{}
	telemetry  *telemetry.Component
}

// NewReconcilerRunner creates a new ReconcilerRunner.
func NewReconcilerRunner(
	reconciler Reconciler,
	opts ...ReconcilerOption,
) ReconcilerRunner {
	cfg := getReconcilerConfig(opts...)
	return &reconcilerRunner{
		reconciler: reconciler,
		trigger:    make(chan struct{}, 1),
		telemetry:  telemetry.NewComponent(cfg.tracerProvider, zerolog.InfoLevel, "databroker-reconciler", cfg.attributes...),
	}
}

// TriggerSync triggers a sync.
func (rr *reconcilerRunner) TriggerSync() {
	select {
	case rr.trigger <- struct{}{}:
	default:
	}
}

// Run runs the reconciler.
func (rr *reconcilerRunner) Run(ctx context.Context) error {
	return rr.reconcileLoop(ctx)
}

func (rr *reconcilerRunner) reconcileLoop(ctx context.Context) error {
	ctx, g := rr.telemetry.Active(ctx, "ReconcileLoop")
	defer g.Done()

	for {
		err := rr.reconciler.Reconcile(ctx)
		if err != nil {
			log.Ctx(ctx).Error().Err(err).Msg("error reconciling")
		}

		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case <-rr.trigger:
		}
	}
}
