package reporter

import (
	"context"
	"errors"
	"fmt"

	export_grpc "go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/resource"
	"google.golang.org/grpc"
)

type metricsReporter struct {
	exporter  *export_grpc.Exporter
	resource  *resource.Resource
	reader    *metric.ManualReader
	producers []metric.Producer
}

func newMetricsReporter(
	ctx context.Context,
	conn *grpc.ClientConn,
	resource *resource.Resource,
	producers []metric.Producer,
) (*metricsReporter, error) {
	exporter, err := export_grpc.New(ctx, export_grpc.WithGRPCConn(conn))
	if err != nil {
		return nil, fmt.Errorf("create exporter: %w", err)
	}
	readerOpts := make([]metric.ManualReaderOption, 0, len(producers))
	for _, p := range producers {
		readerOpts = append(readerOpts, metric.WithProducer(p))
	}
	reader := metric.NewManualReader(readerOpts...)
	_ = metric.NewMeterProvider(
		metric.WithResource(resource),
		metric.WithReader(reader),
	)
	return &metricsReporter{
		exporter:  exporter,
		resource:  resource,
		reader:    reader,
		producers: producers,
	}, nil
}

func (r *metricsReporter) Run(ctx context.Context) error {
	<-ctx.Done()
	return nil
}

func (r *metricsReporter) Shutdown(ctx context.Context) error {
	return errors.Join(
		r.reader.Shutdown(ctx),
		r.exporter.Shutdown(ctx),
	)
}

func (r *metricsReporter) CollectAndExportMetrics(ctx context.Context) error {
	rm := &metricdata.ResourceMetrics{
		Resource: r.resource,
	}
	err := r.reader.Collect(ctx, rm)
	if err != nil {
		return fmt.Errorf("collect metrics: %w", err)
	}

	err = r.exporter.Export(ctx, rm)
	if err != nil {
		return fmt.Errorf("export metrics: %w", err)
	}
	return nil
}
