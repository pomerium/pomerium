package trace

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
)

type systemContextKeyType struct{}

var systemContextKey systemContextKeyType

type Options struct {
	DebugLevel int
}

type systemContext struct {
	Options
	tpm            *tracerProviderManager
	exporterServer *ExporterServer
}

func systemContextFromContext(ctx context.Context) *systemContext {
	return ctx.Value(systemContextKey).(*systemContext)
}

func init() {
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))
	otel.SetTracerProvider(panicTracerProvider{})
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
	var remoteClient otlptrace.Client
	if os.Getenv("OTEL_EXPORTER_OTLP_PROTOCOL") == "http/protobuf" {
		remoteClient = otlptracehttp.NewClient()
	} else {
		remoteClient = otlptracegrpc.NewClient()
	}
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

func NewTracerProvider(ctx context.Context, serviceName string) trace.TracerProvider {
	_, file, line, _ := runtime.Caller(1)
	sys := systemContextFromContext(ctx)
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
	options := []sdktrace.TracerProviderOption{
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(r),
	}
	for _, proc := range sys.exporterServer.SpanProcessors() {
		options = append(options, sdktrace.WithSpanProcessor(proc))
	}
	if sys.DebugLevel >= 1 {
		options = append(options,
			sdktrace.WithSpanProcessor(&stackTraceProcessor{}),
		)
	}
	tp := sdktrace.NewTracerProvider(options...)
	sys.tpm.Add(tp)
	return tp
}

func ShutdownContext(ctx context.Context) error {
	var errs []error
	sys := systemContextFromContext(ctx)

	if err := sys.tpm.ShutdownAll(context.Background()); err != nil {
		errs = append(errs, fmt.Errorf("(*tracerProviderManager).ShutdownAll: %w", err))
	}
	if err := sys.exporterServer.Shutdown(context.Background()); err != nil {
		errs = append(errs, fmt.Errorf("(*Server).Shutdown: %w", err))
	}
	return errors.Join(errs...)
}

func ExporterServerFromContext(ctx context.Context) coltracepb.TraceServiceServer {
	return systemContextFromContext(ctx).exporterServer
}

func WaitForSpans(ctx context.Context, maxDuration time.Duration) error {
	return systemContextFromContext(ctx).exporterServer.spanExportQueue.WaitForSpans(maxDuration)
}
