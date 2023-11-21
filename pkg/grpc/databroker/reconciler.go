package databroker

import (
	"context"
	"fmt"
	"time"

	"github.com/rs/zerolog"
	"golang.org/x/sync/errgroup"

	"github.com/pomerium/pomerium/internal/log"
)

// Reconciler reconciles the target and current record sets with the databroker.
type Reconciler struct {
	reconcilerConfig
	name                string
	client              DataBrokerServiceClient
	currentStateBuilder StateBuilderFn
	cmpFn               RecordCompareFn
	targetStateBuilder  StateBuilderFn
	setCurrentState     func([]*Record)
	trigger             chan struct{}
}

type reconcilerConfig struct {
	interval time.Duration
}

// ReconcilerOption is an option for a reconciler.
type ReconcilerOption func(*reconcilerConfig)

// WithInterval sets the interval for the reconciler.
func WithInterval(interval time.Duration) ReconcilerOption {
	return func(c *reconcilerConfig) {
		c.interval = interval
	}
}

func getReconcilerConfig(options ...ReconcilerOption) reconcilerConfig {
	options = append([]ReconcilerOption{
		WithInterval(time.Minute),
	}, options...)
	var c reconcilerConfig
	for _, option := range options {
		option(&c)
	}
	return c
}

// StateBuilderFn is a function that builds a record set bundle
type StateBuilderFn func(ctx context.Context) (RecordSetBundle, error)

// NewReconciler creates a new reconciler
func NewReconciler(
	// name must be unique across pomerium ecosystem
	name string,
	client DataBrokerServiceClient,
	currentStateBuilder StateBuilderFn,
	targetStateBuilder StateBuilderFn,
	setCurrentState func([]*Record),
	cmpFn RecordCompareFn,
	opts ...ReconcilerOption,
) *Reconciler {
	return &Reconciler{
		name:                fmt.Sprintf("%s-reconciler", name),
		reconcilerConfig:    getReconcilerConfig(opts...),
		trigger:             make(chan struct{}, 1),
		client:              client,
		currentStateBuilder: currentStateBuilder,
		targetStateBuilder:  targetStateBuilder,
		setCurrentState:     setCurrentState,
		cmpFn:               cmpFn,
	}
}

// TriggerSync triggers a sync
func (r *Reconciler) TriggerSync() {
	select {
	case r.trigger <- struct{}{}:
	default:
	}
}

// Run runs the reconciler
func (r *Reconciler) Run(ctx context.Context) error {
	leaser := NewLeaser(r.name, r.interval, r)
	return leaser.Run(ctx)
}

// GetDataBrokerServiceClient implements the LeaseHandler interface.
func (r *Reconciler) GetDataBrokerServiceClient() DataBrokerServiceClient {
	return r.client
}

// RunLeased implements the LeaseHandler interface.
func (r *Reconciler) RunLeased(ctx context.Context) error {
	ctx = log.WithContext(ctx, func(c zerolog.Context) zerolog.Context {
		return c.Str("service", r.name)
	})
	return r.reconcileLoop(ctx)
}

func (r *Reconciler) reconcileLoop(ctx context.Context) error {
	for {
		err := r.Reconcile(ctx)
		if err != nil {
			log.Ctx(ctx).Error().Err(err).Msg("reconcile")
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-r.trigger:
		}
	}
}

// Reconcile brings databroker state in line with the target state.
func (r *Reconciler) Reconcile(ctx context.Context) error {
	current, target, err := r.getRecordSets(ctx)
	if err != nil {
		return fmt.Errorf("get config record sets: %w", err)
	}

	updates := GetChangeSet(current, target, r.cmpFn)

	err = r.applyChanges(ctx, updates)
	if err != nil {
		return fmt.Errorf("apply config change set: %w", err)
	}

	r.setCurrentState(updates)
	return nil
}

func (r *Reconciler) getRecordSets(ctx context.Context) (
	current RecordSetBundle,
	target RecordSetBundle,
	_ error,
) {
	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(func() error {
		var err error
		current, err = r.currentStateBuilder(ctx)
		if err != nil {
			return fmt.Errorf("build current config record set: %w", err)
		}
		return nil
	})
	eg.Go(func() error {
		var err error
		target, err = r.targetStateBuilder(ctx)
		if err != nil {
			return fmt.Errorf("build target config record set: %w", err)
		}
		return nil
	})
	err := eg.Wait()
	if err != nil {
		return nil, nil, err
	}
	return current, target, nil
}

func (r *Reconciler) applyChanges(ctx context.Context, updates []*Record) error {
	err := PutMulti(ctx, r.client, updates...)
	if err != nil {
		return fmt.Errorf("apply databroker changes: %w", err)
	}

	return nil
}
