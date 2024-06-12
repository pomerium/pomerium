package reporter

import (
	"context"
	"errors"
	"fmt"

	export_grpc "go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	metric_sdk "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/resource"
	"google.golang.org/grpc"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/health"
)

type metricsReporter struct {
	exporter  *export_grpc.Exporter
	resource  *resource.Resource
	reader    *metric_sdk.ManualReader
	producers map[string]*metricsProducer
	singleTask
}

func newMetricsReporter(
	ctx context.Context,
	conn *grpc.ClientConn,
	resource *resource.Resource,
	producers map[string]*metricsProducer,
) (*metricsReporter, error) {
	exporter, err := export_grpc.New(ctx, export_grpc.WithGRPCConn(conn))
	if err != nil {
		return nil, fmt.Errorf("create exporter: %w", err)
	}
	readerOpts := make([]metric_sdk.ManualReaderOption, 0, len(producers))
	for _, p := range producers {
		readerOpts = append(readerOpts, metric_sdk.WithProducer(p))
	}
	reader := metric_sdk.NewManualReader(readerOpts...)
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

func (r *metricsReporter) SetMetricProducerEnabled(name string, enabled bool) error {
	p, ok := r.producers[name]
	if !ok {
		return fmt.Errorf("producer %q not found", name)
	}
	p.SetEnabled(enabled)
	return nil
}

func (r *metricsReporter) CollectAndExportMetrics(ctx context.Context) {
	r.singleTask.Run(ctx, func(ctx context.Context) {
		err := r.collectAndExport(ctx)
		if errors.Is(err, ErrAnotherExecutionRequested) {
			log.Warn(ctx).Msg("telemetry metrics were not sent, due to another execution requested")
			return
		}
		if err != nil {
			health.ReportError(health.CollectAndSendTelemetry, err)
		} else {
			health.ReportOK(health.CollectAndSendTelemetry)
		}
	})
}

func (r *metricsReporter) collectAndExport(ctx context.Context) error {
	rm := &metricdata.ResourceMetrics{
		Resource: r.resource,
	}
	err := withBackoff(ctx, "collect metrics", func(ctx context.Context) error { return r.reader.Collect(ctx, rm) })
	if err != nil {
		return fmt.Errorf("collect metrics: %w", err)
	}

	err = withBackoff(ctx, "export metrics", func(ctx context.Context) error { return r.exporter.Export(ctx, rm) })
	if err != nil {
		return fmt.Errorf("export metrics: %w", err)
	}
	return nil
}
