package healthcheck

import (
	"context"
	"fmt"
	"os"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	export_grpc "go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/sdk/resource"
	trace_sdk "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.4.0"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/version"
	"github.com/pomerium/pomerium/pkg/health"
)

type Provider struct {
	exporter *otlptrace.Exporter
	tracer   trace.Tracer
}

var _ health.Provider = (*Provider)(nil)

const (
	shutdownTimeout = 30 * time.Second
	serviceName     = "pomerium-managed-core"
)

// NewReporter creates a new unstarted health check reporter
func NewReporter(
	conn *grpc.ClientConn,
) *Provider {
	p := new(Provider)
	p.init(conn)

	return p
}

func (p *Provider) Run(ctx context.Context) error {
	health.SetProvider(p)
	defer health.SetProvider(nil)

	// we want the exporter
	xc, cancel := context.WithCancel(context.WithoutCancel(ctx))
	defer cancel()

	err := p.exporter.Start(xc)
	if err != nil {
		// this should not happen for the gRPC exporter as its non-blocking
		return fmt.Errorf("error starting health check exporter: %w", err)
	}

	<-ctx.Done()
	return p.shutdown(xc)
}

func (p *Provider) shutdown(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, shutdownTimeout)
	defer cancel()

	return p.exporter.Shutdown(ctx)
}

func (p *Provider) init(conn *grpc.ClientConn) {
	p.initExporter(conn)
	p.initTracer()
}

func (p *Provider) initExporter(conn *grpc.ClientConn) {
	p.exporter = export_grpc.NewUnstarted(export_grpc.WithGRPCConn(conn))
}

func (p *Provider) initTracer() {
	processor := trace_sdk.NewBatchSpanProcessor(p.exporter)
	provider := trace_sdk.NewTracerProvider(
		trace_sdk.WithResource(p.getResource()),
		trace_sdk.WithSampler(trace_sdk.AlwaysSample()),
		trace_sdk.WithSpanProcessor(processor),
	)
	p.tracer = provider.Tracer(serviceName)
}

func (p *Provider) getResource() *resource.Resource {
	attr := []attribute.KeyValue{
		semconv.ServiceNameKey.String(serviceName),
		semconv.ServiceVersionKey.String(version.FullVersion()),
	}

	hostname, err := os.Hostname()
	if err == nil {
		attr = append(attr, semconv.HostNameKey.String(hostname))
	}

	return resource.NewSchemaless(attr...)
}

func (p *Provider) ReportOK(check health.Check, attr ...health.Attr) {
	ctx := context.Background()
	log.Ctx(ctx).Debug().Str("check", string(check)).Msg("health check ok")
	_, span := p.tracer.Start(ctx, string(check))
	span.SetStatus(codes.Ok, "")
	setAttributes(span, attr...)
	span.End()
}

func (p *Provider) ReportError(check health.Check, err error, attr ...health.Attr) {
	ctx := context.Background()
	log.Ctx(ctx).Warn().Str("check", string(check)).Err(err).Msg("health check error")
	_, span := p.tracer.Start(ctx, string(check))
	span.SetStatus(codes.Error, err.Error())
	setAttributes(span, attr...)
	span.End()
}

func setAttributes(span trace.Span, attr ...health.Attr) {
	for _, a := range attr {
		span.SetAttributes(attribute.String(a.Key, a.Value))
	}
}
