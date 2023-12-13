// Package reporter periodically submits metrics back to the cloud.
package reporter

import (
	"context"
	"fmt"
	"time"

	export_grpc "go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	metric_sdk "go.opentelemetry.io/otel/sdk/metric"
	"google.golang.org/grpc"

	"github.com/pomerium/pomerium/internal/log"
)

// Run starts loop that pushes metrics via OTEL protocol until ctx is canceled
func Run(
	ctx context.Context,
	conn *grpc.ClientConn,
	opts ...Option,
) error {
	cfg := getConfig(opts...)

	exporter, err := export_grpc.New(ctx, export_grpc.WithGRPCConn(conn))
	if err != nil {
		return fmt.Errorf("starting OTEL exporter: %w", err)
	}
	defer shutdown(exporter.Shutdown, cfg.shutdownTimeout)

	provider := metric_sdk.NewMeterProvider(
		metric_sdk.WithReader(
			metric_sdk.NewPeriodicReader(
				exporter,
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
