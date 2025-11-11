// Package reporter periodically submits metrics back to the cloud.
package reporter

import (
	"context"
	"fmt"
	"os"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.4.0"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"

	"github.com/pomerium/pomerium/internal/retry"
	"github.com/pomerium/pomerium/internal/version"
)

type Reporter struct {
	*metricsReporter
	*healthCheckReporter
}

const (
	serviceName = "pomerium-managed-core"
)

// New creates a new unstarted zero telemetry reporter
func New(
	ctx context.Context,
	conn *grpc.ClientConn,
	opts ...Option,
) (*Reporter, error) {
	cfg := getConfig(opts...)
	resource := getResource()

	metrics, err := newMetricsReporter(ctx, conn, resource, cfg.producers)
	if err != nil {
		return nil, fmt.Errorf("failed to create metrics reporter: %w", err)
	}

	healthChecks := newHealthCheckReporter(conn, resource)

	return &Reporter{
		metricsReporter:     metrics,
		healthCheckReporter: healthChecks,
	}, nil
}

func (r *Reporter) Run(ctx context.Context) error {
	eg, ctx := errgroup.WithContext(ctx)

	eg.Go(func() error { return retry.WithBackoff(ctx, "metrics reporter", r.metricsReporter.Run) })
	eg.Go(func() error { return retry.WithBackoff(ctx, "health check reporter", r.healthCheckReporter.Run) })

	return eg.Wait()
}

// Shutdown should be called after Run to cleanly shutdown the reporter
func (r *Reporter) Shutdown(ctx context.Context) error {
	eg, ctx := errgroup.WithContext(ctx)

	eg.Go(func() error { return r.metricsReporter.Shutdown(ctx) })
	eg.Go(func() error { return r.healthCheckReporter.Shutdown(ctx) })

	return eg.Wait()
}

func getResource() *resource.Resource {
	attr := []attribute.KeyValue{
		semconv.ServiceNameKey.String(serviceName),
		semconv.ServiceVersionKey.String(version.FullVersion()),
	}

	for k, v := range version.Components() {
		attr = append(attr, attribute.String("pomerium."+k+".version", v))
	}

	hostname, err := os.Hostname()
	if err == nil {
		attr = append(attr, semconv.HostNameKey.String(hostname))
	}

	return resource.NewSchemaless(attr...)
}
