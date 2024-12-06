package trace

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
)

type systemContextKeyType struct{}

var systemContextKey systemContextKeyType

type Options struct {
	DebugFlags DebugFlags
}

type systemContext struct {
	Options
	tpm            *tracerProviderManager
	exporterServer *ExporterServer
}

func systemContextFromContext(ctx context.Context) *systemContext {
	sys, _ := ctx.Value(systemContextKey).(*systemContext)
	return sys
}

var _ trace.Tracer = panicTracer{}

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

func (op Options) NewContext(ctx context.Context) context.Context {
	remoteClient := NewRemoteClientFromEnv()
	sys := &systemContext{
		Options: op,
		tpm:     &tracerProviderManager{},
	}
	ctx = context.WithValue(ctx, systemContextKey, sys)
	sys.exporterServer = NewServer(ctx, remoteClient)
	sys.exporterServer.Start(ctx)

	return ctx
}

func NewContext(ctx context.Context) context.Context {
	return Options{}.NewContext(ctx)
}

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
	options := append([]sdktrace.TracerProviderOption{
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(r),
	}, opts...)
	for _, proc := range sys.exporterServer.SpanProcessors() {
		options = append(options, sdktrace.WithSpanProcessor(proc))
	}
	if sys.DebugFlags.Check(TrackSpanCallers) {
		options = append(options,
			sdktrace.WithSpanProcessor(&stackTraceProcessor{}),
		)
	}
	tp := sdktrace.NewTracerProvider(options...)
	sys.tpm.Add(tp)
	return tp
}

func ShutdownContext(ctx context.Context) error {
	sys := systemContextFromContext(ctx)
	if sys == nil {
		return nil
	}

	var errs []error
	if err := sys.tpm.ShutdownAll(context.Background()); err != nil {
		errs = append(errs, fmt.Errorf("error shutting down tracer providers: %w", err))
	}
	if err := sys.exporterServer.Shutdown(context.Background()); err != nil {
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

func WaitForSpans(ctx context.Context, maxDuration time.Duration) error {
	if sys := systemContextFromContext(ctx); sys != nil {
		return sys.exporterServer.spanExportQueue.WaitForSpans(maxDuration)
	}
	return nil
}
