package trace

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"

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
	"go.opentelemetry.io/otel/trace/embedded"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/stats"
)

type (
	clientKeyType         struct{}
	exporterKeyType       struct{}
	tracerProviderKeyType struct{}
	serverKeyType         struct{}
)

var (
	exporterKey       exporterKeyType
	tracerProviderKey tracerProviderKeyType
	serverKey         serverKeyType
)

type shutdownFunc func(options ...trace.SpanEndOption)

func init() {
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))
	otel.SetTracerProvider(panicTracerProvider{})
}

type panicTracerProvider struct {
	embedded.TracerProvider
}

// Tracer implements trace.TracerProvider.
func (w panicTracerProvider) Tracer(name string, options ...trace.TracerOption) trace.Tracer {
	panic("global tracer used")
}

func NewContext(ctx context.Context) context.Context {
	var realClient otlptrace.Client
	if os.Getenv("OTEL_EXPORTER_OTLP_PROTOCOL") == "http/protobuf" {
		realClient = otlptracehttp.NewClient()
	} else {
		realClient = otlptracegrpc.NewClient()
	}
	srv := NewServer(ctx, realClient)
	localClient := srv.Start(ctx)
	exp, err := otlptrace.New(ctx, localClient)
	if err != nil {
		panic(err)
	}
	ctx = context.WithValue(ctx, exporterKey, exp)
	ctx = context.WithValue(ctx, serverKey, srv)
	return ctx
}

func NewTracerProvider(ctx context.Context, serviceName string) trace.TracerProvider {
	_, file, line, _ := runtime.Caller(1)
	exp := ctx.Value(exporterKey).(sdktrace.SpanExporter)
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
	return sdktrace.NewTracerProvider(
		sdktrace.WithSpanProcessor(&stackTraceProcessor{}),
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(r),
	)
}

type stackTraceProcessor struct{}

// ForceFlush implements trace.SpanProcessor.
func (s *stackTraceProcessor) ForceFlush(ctx context.Context) error {
	return nil
}

// OnEnd implements trace.SpanProcessor.
func (*stackTraceProcessor) OnEnd(s sdktrace.ReadOnlySpan) {
}

// OnStart implements trace.SpanProcessor.
func (*stackTraceProcessor) OnStart(parent context.Context, s sdktrace.ReadWriteSpan) {
	_, file, line, _ := runtime.Caller(2)
	s.SetAttributes(attribute.String("caller", fmt.Sprintf("%s:%d", file, line)))
}

// Shutdown implements trace.SpanProcessor.
func (s *stackTraceProcessor) Shutdown(ctx context.Context) error {
	return nil
}

func ForceFlush(ctx context.Context) error {
	if tp, ok := trace.SpanFromContext(ctx).TracerProvider().(interface {
		ForceFlush(context.Context) error
	}); ok {
		return tp.ForceFlush(context.Background())
	}
	return nil
}

func Shutdown(ctx context.Context) error {
	_ = ForceFlush(ctx)
	exporter := ctx.Value(exporterKey).(sdktrace.SpanExporter)
	return exporter.Shutdown(context.Background())
}

func ExporterServerFromContext(ctx context.Context) coltracepb.TraceServiceServer {
	return ctx.Value(serverKey).(coltracepb.TraceServiceServer)
}

const PomeriumCoreTracer = "pomerium.io/core"

// StartSpan starts a new child span of the current span in the context. If
// there is no span in the context, creates a new trace and span.
//
// Returned context contains the newly created span. You can use it to
// propagate the returned span in process.
func Continue(ctx context.Context, name string, o ...trace.SpanStartOption) (context.Context, trace.Span) {
	return trace.SpanFromContext(ctx).TracerProvider().Tracer(PomeriumCoreTracer).Start(ctx, name, o...)
}

func ParseTraceparent(traceparent string) (trace.SpanContext, error) {
	parts := strings.Split(traceparent, "-")
	if len(parts) != 4 {
		return trace.SpanContext{}, errors.New("malformed traceparent")
	}
	traceId, err := trace.TraceIDFromHex(parts[1])
	if err != nil {
		return trace.SpanContext{}, err
	}
	spanId, err := trace.SpanIDFromHex(parts[2])
	if err != nil {
		return trace.SpanContext{}, err
	}
	traceFlags, err := strconv.ParseUint(parts[3], 6, 32)
	if err != nil {
		return trace.SpanContext{}, err
	}
	if len(traceId) != 16 || len(spanId) != 8 {
		return trace.SpanContext{}, errors.New("malformed traceparent")
	}
	return trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    traceId,
		SpanID:     spanId,
		TraceFlags: trace.TraceFlags(traceFlags),
	}), nil
}

func ReplaceTraceID(traceparent string, newTraceID trace.TraceID) string {
	parts := strings.Split(traceparent, "-")
	if len(parts) != 4 {
		return traceparent
	}
	parts[1] = hex.EncodeToString(newTraceID[:])
	return strings.Join(parts, "-")
}

func NewStatsHandler(base stats.Handler) stats.Handler {
	return &wrapperStatsHandler{
		base: base,
	}
}

type wrapperStatsHandler struct {
	base stats.Handler
}

func (w *wrapperStatsHandler) wrapContext(ctx context.Context) context.Context {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ctx
	}
	traceparent := md.Get("traceparent")
	xPomeriumTraceparent := md.Get("x-pomerium-traceparent")
	if len(traceparent) > 0 && traceparent[0] != "" && len(xPomeriumTraceparent) > 0 && xPomeriumTraceparent[0] != "" {
		newTracectx, err := ParseTraceparent(xPomeriumTraceparent[0])
		if err != nil {
			return ctx
		}

		md.Set("traceparent", ReplaceTraceID(traceparent[0], newTracectx.TraceID()))
		return metadata.NewIncomingContext(ctx, md)
	}
	return ctx
}

// HandleConn implements stats.Handler.
func (w *wrapperStatsHandler) HandleConn(ctx context.Context, stats stats.ConnStats) {
	w.base.HandleConn(w.wrapContext(ctx), stats)
}

// HandleRPC implements stats.Handler.
func (w *wrapperStatsHandler) HandleRPC(ctx context.Context, stats stats.RPCStats) {
	w.base.HandleRPC(w.wrapContext(ctx), stats)
}

// TagConn implements stats.Handler.
func (w *wrapperStatsHandler) TagConn(ctx context.Context, info *stats.ConnTagInfo) context.Context {
	return w.base.TagConn(w.wrapContext(ctx), info)
}

// TagRPC implements stats.Handler.
func (w *wrapperStatsHandler) TagRPC(ctx context.Context, info *stats.RPCTagInfo) context.Context {
	return w.base.TagRPC(w.wrapContext(ctx), info)
}
