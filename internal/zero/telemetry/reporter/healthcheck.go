package reporter

import (
	"context"
	"errors"
	"fmt"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	export_grpc "go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/sdk/resource"
	trace_sdk "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/health"
)

type healthCheckReporter struct {
	resource *resource.Resource
	exporter *otlptrace.Exporter
	provider *trace_sdk.TracerProvider
	tracer   trace.Tracer
}

// NewhealthCheckReporter creates a new unstarted health check healthCheckReporter
func newHealthCheckReporter(
	conn *grpc.ClientConn,
	resource *resource.Resource,
) *healthCheckReporter {
	exporter := export_grpc.NewUnstarted(export_grpc.WithGRPCConn(conn))
	processor := trace_sdk.NewBatchSpanProcessor(exporter)
	provider := trace_sdk.NewTracerProvider(
		trace_sdk.WithResource(resource),
		trace_sdk.WithSampler(trace_sdk.AlwaysSample()),
		trace_sdk.WithSpanProcessor(processor),
	)
	tracer := provider.Tracer(serviceName)

	return &healthCheckReporter{
		resource: resource,
		exporter: exporter,
		tracer:   tracer,
		provider: provider,
	}
}

func (r *healthCheckReporter) Run(ctx context.Context) error {
	err := r.exporter.Start(ctx)
	if err != nil {
		// this should not happen for the gRPC exporter as its non-blocking
		return fmt.Errorf("error starting health check exporter: %w", err)
	}

	<-ctx.Done()
	return nil
}

func (r *healthCheckReporter) Shutdown(ctx context.Context) error {
	return errors.Join(
		r.provider.Shutdown(ctx),
		r.exporter.Shutdown(ctx),
	)
}

// ReportStatus implements health.Provider interface
func (r *healthCheckReporter) ReportStatus(check health.Check, status health.Status, attr ...health.Attr) {
	ctx := context.Background()
	log.Ctx(ctx).Debug().Str("check", string(check)).
		Str("status", status.String()).Msg("health check ok")

	// Starting & Terminating statuses are left as no-op for now, for backwards compatibility
	if status == health.StatusRunning {
		_, span := r.tracer.Start(ctx, string(check))
		span.SetStatus(codes.Ok, "")
		setAttributes(span, attr...)
		span.End()
	}
}

// ReportError implements health.Provider interface
func (r *healthCheckReporter) ReportError(check health.Check, err error, attr ...health.Attr) {
	ctx := context.Background()
	log.Ctx(ctx).Error().Str("check", string(check)).Err(err).Msg("health check error")
	_, span := r.tracer.Start(ctx, string(check))
	span.SetStatus(codes.Error, err.Error())
	setAttributes(span, attr...)
	span.End()
}

func setAttributes(span trace.Span, attr ...health.Attr) {
	for _, a := range attr {
		span.SetAttributes(attribute.String(a.Key, a.Value))
	}
}
