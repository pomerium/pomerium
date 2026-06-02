package databrokerutil

import (
	"context"
	"fmt"

	"github.com/rs/zerolog"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
)

type ReconcilerRunner interface {
	LeaserHandler
	Run(context.Context) error
	TriggerSync()
}

type reconcilerRunner struct {
	reconcilerConfig
	reconciler Reconciler
	client     databrokerpb.DataBrokerServiceClient
	name       string
	trigger    chan struct{}
	telemetry  *telemetry.Component
}

// NewReconcilerRunner creates a new ReconcilerRunner.
func NewReconcilerRunner(
	reconciler Reconciler,
	leaseName string, // must be unique across pomerium ecosystem
	client databrokerpb.DataBrokerServiceClient,
	opts ...ReconcilerOption,
) ReconcilerRunner {
	cfg := getReconcilerConfig(opts...)
	return &reconcilerRunner{
		reconcilerConfig: cfg,
		reconciler:       reconciler,
		client:           client,
		name:             fmt.Sprintf("%s-reconciler", leaseName),
		trigger:          make(chan struct{}, 1),
		telemetry:        telemetry.NewComponent(cfg.tracerProvider, zerolog.InfoLevel, "databroker-reconciler", cfg.attributes...),
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
	leaser := NewLeaser(rr.name, rr.interval, rr, WithLeaserErrorHandler(rr.errorHandler))
	return leaser.Run(ctx)
}

// GetDataBrokerServiceClient implements the LeaseHandler interface.
func (rr *reconcilerRunner) GetDataBrokerServiceClient() databrokerpb.DataBrokerServiceClient {
	return rr.client
}

// RunLeased implements the LeaseHandler interface.
func (rr *reconcilerRunner) RunLeased(ctx context.Context) error {
	ctx = log.WithContext(ctx, func(c zerolog.Context) zerolog.Context {
		return c.Str("service", rr.name)
	})
	return rr.reconcileLoop(ctx)
}

func (rr *reconcilerRunner) reconcileLoop(ctx context.Context) error {
	ctx, g := rr.telemetry.Active(ctx, "ReconcileLoop")
	defer g.Done()

	for {
		err := rr.reconciler.Reconcile(ctx)
		if err != nil {
			log.Ctx(ctx).Error().Err(err).Msg("reconcile")
		}

		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case <-rr.trigger:
		}
	}
}
