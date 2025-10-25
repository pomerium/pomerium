package databroker

import (
	"context"
	"fmt"
	"time"

	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel/attribute"
	oteltrace "go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
	"golang.org/x/sync/errgroup"

	"github.com/pomerium/pomerium/internal/telemetry"
)

// Reconciler reconciles the target and current record sets with the databroker.
type Reconciler interface {
	Reconcile(context.Context) error
}

type reconciler struct {
	reconcilerConfig
	client              DataBrokerServiceClient
	currentStateBuilder StateBuilderFn
	cmpFn               RecordCompareFn
	targetStateBuilder  StateBuilderFn
	setCurrentState     func([]*Record)
	telemetry           *telemetry.Component
}

type reconcilerConfig struct {
	attributes     []attribute.KeyValue
	interval       time.Duration
	tracerProvider oteltrace.TracerProvider
}

// ReconcilerOption is an option for a reconciler.
type ReconcilerOption func(cfg *reconcilerConfig)

// WithAttributes sets the attributes for the reconciler.
func WithAttributes(attributes ...attribute.KeyValue) ReconcilerOption {
	return func(cfg *reconcilerConfig) {
		cfg.attributes = append(cfg.attributes, attributes...)
	}
}

// WithInterval sets the interval for the reconciler.
func WithInterval(interval time.Duration) ReconcilerOption {
	return func(cfg *reconcilerConfig) {
		cfg.interval = interval
	}
}

// WithReconcilerTracerProvider sets the tracer provider for the reconciler.
func WithReconcilerTracerProvider(tracerProvider oteltrace.TracerProvider) ReconcilerOption {
	return func(cfg *reconcilerConfig) {
		cfg.tracerProvider = tracerProvider
	}
}

func getReconcilerConfig(options ...ReconcilerOption) reconcilerConfig {
	options = append([]ReconcilerOption{
		WithInterval(time.Minute),
		WithReconcilerTracerProvider(noop.NewTracerProvider()),
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
	client DataBrokerServiceClient,
	currentStateBuilder StateBuilderFn,
	targetStateBuilder StateBuilderFn,
	setCurrentState func([]*Record),
	cmpFn RecordCompareFn,
	opts ...ReconcilerOption,
) Reconciler {
	cfg := getReconcilerConfig(opts...)
	return &reconciler{
		reconcilerConfig:    cfg,
		client:              client,
		currentStateBuilder: currentStateBuilder,
		targetStateBuilder:  targetStateBuilder,
		setCurrentState:     setCurrentState,
		cmpFn:               cmpFn,
		telemetry:           telemetry.NewComponent(cfg.tracerProvider, zerolog.InfoLevel, "databroker-reconciler", cfg.attributes...),
	}
}

// Reconcile brings databroker state in line with the target state.
func (r *reconciler) Reconcile(ctx context.Context) error {
	ctx, op := r.telemetry.Start(ctx, "Reconcile")
	defer op.Complete()

	current, target, err := r.getRecordSets(ctx)
	if err != nil {
		return op.Failure(fmt.Errorf("get config record sets: %w", err))
	}

	updates := GetChangeSet(current, target, r.cmpFn)

	err = r.applyChanges(ctx, updates)
	if err != nil {
		return op.Failure(fmt.Errorf("apply config change set: %w", err))
	}

	r.setCurrentState(updates)
	return nil
}

func (r *reconciler) getRecordSets(ctx context.Context) (
	current RecordSetBundle,
	target RecordSetBundle,
	_ error,
) {
	ctx, op := r.telemetry.Start(ctx, "GetRecordSets")
	defer op.Complete()

	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(func() error {
		var err error
		ctx, op := r.telemetry.Start(ctx, "CurrentStateBuilder")
		defer op.Complete()

		current, err = r.currentStateBuilder(ctx)
		if err != nil {
			return op.Failure(fmt.Errorf("build current config record set: %w", err))
		}
		return nil
	})
	eg.Go(func() error {
		var err error
		ctx, op := r.telemetry.Start(ctx, "TargetStateBuilder")
		defer op.Complete()

		target, err = r.targetStateBuilder(ctx)
		if err != nil {
			return op.Failure(fmt.Errorf("build target config record set: %w", err))
		}
		return nil
	})

	err := eg.Wait()
	if err != nil {
		return nil, nil, op.Failure(fmt.Errorf("wait for record sets: %w", err))
	}
	return current, target, nil
}

func (r *reconciler) applyChanges(ctx context.Context, updates []*Record) error {
	ctx, op := r.telemetry.Start(ctx, "ApplyChanges")
	defer op.Complete()

	err := PutMulti(ctx, r.client, updates...)
	if err != nil {
		return op.Failure(fmt.Errorf("apply databroker changes: %w", err))
	}

	return nil
}
