package telemetry

import (
	"context"
	"fmt"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	oteltrace "go.opentelemetry.io/otel/trace"

	"github.com/pomerium/pomerium/pkg/telemetry/trace"
)

// A Component represents a component of Pomerium and is used to trace and log operations
type Component struct {
	logLevel       zerolog.Level
	component      string
	attributes     []attribute.KeyValue
	tracer         oteltrace.Tracer
	tracerProvider oteltrace.TracerProvider
}

// NewComponent creates a new Component.
func NewComponent(tracerProvider oteltrace.TracerProvider, logLevel zerolog.Level, component string, attributes ...attribute.KeyValue) *Component {
	tracer := tracerProvider.Tracer(trace.PomeriumCoreTracer)

	c := &Component{
		logLevel:       logLevel,
		component:      component,
		tracer:         tracer,
		tracerProvider: tracerProvider,
		attributes: append([]attribute.KeyValue{
			attribute.String("component", component),
		}, attributes...),
	}
	return c
}

func (c *Component) Active(ctx context.Context, name string, attributes ...attribute.KeyValue) (context.Context, *ActiveGauge) {
	ctx = logger(ctx, attributes...).WithContext(ctx)
	g := newGauge(ctx, c, name, attributes...)
	return ctx, g
}

// Start starts an operation.
func (c *Component) Start(ctx context.Context, operationName string, attributes ...attribute.KeyValue) (context.Context, Operation) {
	attributes = append(c.attributes, attributes...)

	// setup tracing
	ctx, span := c.tracer.Start(ctx, c.component+"."+operationName, oteltrace.WithAttributes(attributes...))

	// setup logging
	ctx = logger(ctx, attributes...).WithContext(ctx)

	op := Operation{
		c:     c,
		name:  operationName,
		ctx:   ctx,
		span:  span,
		start: time.Now(),
	}

	return ctx, op
}

func (c *Component) GetTracerProvider() oteltrace.TracerProvider {
	return c.tracerProvider
}

type ActiveGauge struct {
	c   *Component
	g   metric.Int64Gauge
	ctx context.Context
}

func newGauge(ctx context.Context, c *Component, name string, attributes ...attribute.KeyValue) *ActiveGauge {
	g := getGauge(c.component, name)
	attributes = append(c.attributes, attributes...)
	g.Record(ctx, 1, metric.WithAttributes(attributes...))
	return &ActiveGauge{
		c:   c,
		g:   g,
		ctx: ctx,
	}
}

func (g *ActiveGauge) Done() {
	g.g.Record(context.Background(), 0, metric.WithAttributes(g.c.attributes...))
}

// An Operation represents an operation that can be traced and logged.
type Operation struct {
	c     *Component
	name  string
	ctx   context.Context
	span  oteltrace.Span
	done  bool
	start time.Time
}

// Failure logs and traces the operation as an error and returns a wrapped error with additional info.
func (op *Operation) Failure(err error, attributes ...attribute.KeyValue) error {
	op.complete(err, attributes...)
	return fmt.Errorf("%s: %s failed: %w", op.c.component, op.name, err)
}

// Complete completes an operation.
func (op *Operation) Complete(attributes ...attribute.KeyValue) {
	op.complete(nil, attributes...)
}

func (op *Operation) complete(err error, attributes ...attribute.KeyValue) {
	if op.done {
		return
	}
	op.done = true

	attributes = append(op.c.attributes, attributes...)

	getInt64Counter(op.c.component, op.name+".calls").Add(op.ctx, 1, metric.WithAttributes(attributes...))
	getFloat64Histogram(op.c.component, op.name+".duration", metric.WithUnit("s")).Record(op.ctx, time.Since(op.start).Seconds(), metric.WithAttributes(attributes...))

	if err == nil {
		getInt64Counter(op.c.component, op.name+".successes").Add(op.ctx, 1, metric.WithAttributes(attributes...))

		l := logger(op.ctx, attributes...)
		l.WithLevel(op.c.logLevel).Msgf("%s.%s succeeded", op.c.component, op.name)

		op.span.SetStatus(codes.Ok, "ok")
	} else {
		getInt64Counter(op.c.component, op.name+".failures").Add(op.ctx, 1, metric.WithAttributes(attributes...))

		l := logger(op.ctx, attributes...)
		l.Error().Err(err).Msgf("%s.%s failed", op.c.component, op.name)

		op.span.RecordError(err)
		op.span.SetStatus(codes.Error, err.Error())
	}
	op.span.End()
}

func logger(ctx context.Context, attributes ...attribute.KeyValue) zerolog.Logger {
	logCtx := log.Ctx(ctx).With()
	for _, a := range attributes {
		logCtx = logCtx.Interface(string(a.Key), a.Value.AsInterface())
	}
	return logCtx.Logger()
}
