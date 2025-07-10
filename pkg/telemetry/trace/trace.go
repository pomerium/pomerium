package trace

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.34.0"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
)

type Options struct {
	DebugFlags DebugFlags
}

func (op Options) NewContext(parent context.Context, remoteClient otlptrace.Client) context.Context {
	if systemContextFromContext(parent) != nil {
		panic("parent already contains trace system context")
	}
	if remoteClient == nil {
		panic("remoteClient cannot be nil (use trace.NoopClient instead)")
	}
	sys := &systemContext{
		options:      op,
		remoteClient: remoteClient,
		tpm:          &tracerProviderManager{},
	}
	if op.DebugFlags.Check(TrackSpanReferences) {
		sys.observer = newSpanObserver()
	}
	ctx := context.WithValue(parent, systemContextKey, sys)
	sys.exporterServer = NewServer(ctx)
	sys.exporterServer.Start(ctx)
	return ctx
}

// NewContext creates a new top-level background context with tracing machinery
// and configuration that will be used when creating new tracer providers.
//
// Any context created with NewContext should eventually be shut down by calling
// [ShutdownContext] to ensure all traces are exported.
//
// The parent context should be context.Background(), or a background context
// containing a logger. If any context in the parent's hierarchy was created
// by NewContext, this will panic.
func NewContext(parent context.Context, remoteClient otlptrace.Client) context.Context {
	return Options{}.NewContext(parent, remoteClient)
}

// NewTracerProvider creates a new [trace.TracerProvider] with the given service
// name and options.
//
// A context returned by [NewContext] must exist somewhere in the hierarchy of
// ctx, otherwise a no-op TracerProvider is returned. The configuration embedded
// within that context will be used to configure its resource attributes and
// exporter automatically.
func NewTracerProvider(ctx context.Context, serviceName string, opts ...sdktrace.TracerProviderOption) trace.TracerProvider {
	sys := systemContextFromContext(ctx)
	if sys == nil {
		return noop.NewTracerProvider()
	}
	_, file, line, _ := runtime.Caller(1)
	exp, err := otlptrace.New(ctx, sys.exporterServer.NewClient())
	if err != nil {
		panic(err)
	}
	r, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName(serviceName),
			attribute.String("provider.created_at", fmt.Sprintf("%s:%d", file, line)),
		),
	)
	if err != nil {
		panic(err)
	}
	options := []sdktrace.TracerProviderOption{}
	if sys.options.DebugFlags.Check(TrackSpanCallers) {
		options = append(options, sdktrace.WithSpanProcessor(&stackTraceProcessor{}))
	}
	if sys.options.DebugFlags.Check(TrackSpanReferences) {
		tracker := newSpanTracker(sys.observer, sys.options.DebugFlags)
		options = append(options, sdktrace.WithSpanProcessor(tracker))
	}
	options = append(append(options,
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(r),
	), opts...)
	tp := sdktrace.NewTracerProvider(options...)
	sys.tpm.Add(tp)
	return tp
}

// Continue starts a new span using the tracer provider of the span in the given
// context.
//
// In most cases, it is better to start spans directly from a specific tracer,
// obtained via dependency injection or some other mechanism. This function is
// useful in shared code where the tracer used to start the span is not
// necessarily the same every time, but can change based on the call site.
func Continue(ctx context.Context, name string, o ...trace.SpanStartOption) (context.Context, trace.Span) {
	return trace.SpanFromContext(ctx).
		TracerProvider().
		Tracer(PomeriumCoreTracer).
		Start(ctx, name, o...)
}

// ShutdownContext will gracefully shut down all tracing resources created with
// a context returned by [NewContext], including all tracer providers and the
// underlying exporter and remote client.
//
// This should only be called once before exiting, but subsequent calls are
// a no-op.
//
// The provided context does not necessarily need to be the exact context
// returned by [NewContext]; it can be anywhere in its context hierarchy and
// this function will have the same effect.
func ShutdownContext(ctx context.Context) error {
	sys := systemContextFromContext(ctx)
	if sys == nil {
		panic("context was not created with trace.NewContext")
	}

	if !sys.shutdown.CompareAndSwap(false, true) {
		return nil
	}

	var errs []error
	if err := sys.tpm.ShutdownAll(context.Background()); err != nil {
		errs = append(errs, fmt.Errorf("error shutting down tracer providers: %w", err))
	}
	if err := sys.exporterServer.Shutdown(context.Background()); err != nil && !errors.Is(err, ErrNoClient) {
		errs = append(errs, fmt.Errorf("error shutting down trace exporter: %w", err))
	}
	return errors.Join(errs...)
}

func ExporterServerFromContext(ctx context.Context) coltracepb.TraceServiceServer {
	if sys := systemContextFromContext(ctx); sys != nil {
		return sys.exporterServer
	}
	return nil
}

func RemoteClientFromContext(ctx context.Context) otlptrace.Client {
	if sys := systemContextFromContext(ctx); sys != nil {
		return sys.remoteClient
	}
	return nil
}

// ForceFlush immediately exports all spans that have not yet been exported for
// all tracer providers created using the given context.
func ForceFlush(ctx context.Context) error {
	if sys := systemContextFromContext(ctx); sys != nil {
		var errs []error
		for _, tp := range sys.tpm.tracerProviders {
			errs = append(errs, tp.ForceFlush(ctx))
		}
		return errors.Join(errs...)
	}
	return nil
}

type systemContextKeyType struct{}

var systemContextKey systemContextKeyType

type systemContext struct {
	options        Options
	remoteClient   otlptrace.Client
	tpm            *tracerProviderManager
	observer       *spanObserver
	exporterServer *ExporterServer
	shutdown       atomic.Bool
}

func systemContextFromContext(ctx context.Context) *systemContext {
	sys, _ := ctx.Value(systemContextKey).(*systemContext)
	return sys
}

type tracerProviderManager struct {
	mu              sync.Mutex
	tracerProviders []*sdktrace.TracerProvider
}

func (tpm *tracerProviderManager) ShutdownAll(ctx context.Context) error {
	tpm.mu.Lock()
	defer tpm.mu.Unlock()
	var errs []error
	for _, tp := range tpm.tracerProviders {
		errs = append(errs, tp.ForceFlush(ctx))
	}
	for _, tp := range tpm.tracerProviders {
		errs = append(errs, tp.Shutdown(ctx))
	}
	clear(tpm.tracerProviders)
	return errors.Join(errs...)
}

func (tpm *tracerProviderManager) Add(tp *sdktrace.TracerProvider) {
	tpm.mu.Lock()
	defer tpm.mu.Unlock()
	tpm.tracerProviders = append(tpm.tracerProviders, tp)
}
