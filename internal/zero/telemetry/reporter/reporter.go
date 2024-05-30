// Package reporter periodically submits metrics back to the cloud.
package reporter

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/cenkalti/backoff/v4"
	"go.opentelemetry.io/otel/attribute"
	export_grpc "go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	metric_sdk "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.4.0"
	"google.golang.org/grpc"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/version"
)

type Reporter struct {
	exporter *export_grpc.Exporter
	resource *resource.Resource
}

func New(ctx context.Context, conn *grpc.ClientConn) (*Reporter, error) {
	exporter, err := export_grpc.New(ctx, export_grpc.WithGRPCConn(conn))
	if err != nil {
		return nil, fmt.Errorf("starting OTEL exporter: %w", err)
	}
	return &Reporter{
		exporter: exporter,
		resource: getResource(),
	}, nil
}

func (r *Reporter) ReportMetrics(ctx context.Context, metrics []metricdata.Metrics) error {
	bo := backoff.NewExponentialBackOff()
	bo.MaxElapsedTime = 0

	req := &metricdata.ResourceMetrics{
		Resource: r.resource,
		ScopeMetrics: []metricdata.ScopeMetrics{
			{Metrics: metrics},
		},
	}
	return backoff.RetryNotify(func() error {
		return r.exporter.Export(ctx, req)
	}, backoff.WithContext(bo, ctx), func(err error, d time.Duration) {
		log.Ctx(ctx).Warn().Err(err).Str("retry_in", d.String()).Msg("error exporting metrics")
	})
}

// RunPeriodicMetricReporter starts loop that pushes metrics collected periodically via OTEL protocol until ctx is canceled
func (r *Reporter) RunPeriodicMetricReporter(
	ctx context.Context,
	opts ...Option,
) error {
	cfg := getConfig(opts...)

	provider := metric_sdk.NewMeterProvider(
		metric_sdk.WithResource(r.resource),
		metric_sdk.WithReader(
			metric_sdk.NewPeriodicReader(
				r.exporter,
				metric_sdk.WithInterval(cfg.collectInterval),
			)))
	defer shutdown(provider.Shutdown, cfg.shutdownTimeout)

	meter := provider.Meter("pomerium-managed-core")
	for _, fn := range cfg.metrics {
		err := fn(meter)
		if err != nil {
			log.Ctx(ctx).Error().Err(err).Msg("error registering metric")
		}
	}

	<-ctx.Done()
	return ctx.Err()
}

func shutdown(fn func(ctx context.Context) error, timeout time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	_ = fn(ctx)
}

func getResource() *resource.Resource {
	attr := []attribute.KeyValue{
		semconv.ServiceNameKey.String("pomerium-managed-core"),
		semconv.ServiceVersionKey.String(version.FullVersion()),
	}

	hostname, err := os.Hostname()
	if err == nil {
		attr = append(attr, semconv.HostNameKey.String(hostname))
	}

	return resource.NewSchemaless(attr...)
}
