package controller

import (
	"context"
	"fmt"
	"time"

	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel/sdk/instrumentation"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/zero/healthcheck"
	"github.com/pomerium/pomerium/internal/zero/telemetry/reporter"
	"github.com/pomerium/pomerium/internal/zero/telemetry/sessions"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/health"
)

const (
	producerSessionAnalytics = "session-analytics"
)

func (c *controller) initTelemetry(ctx context.Context, clientProvider func() (databroker.DataBrokerServiceClient, error)) error {
	sessionMetricProducer := sessions.NewProducer(instrumentation.Scope{}, clientProvider)
	r, err := reporter.New(ctx, c.api.GetTelemetryConn(),
		reporter.WithProducer(producerSessionAnalytics, sessionMetricProducer),
	)
	if err != nil {
		return fmt.Errorf("error creating telemetry metrics reporter: %w", err)
	}
	c.telemetryReporter = r
	return nil
}

func (c *controller) runSessionAnalyticsLeased(ctx context.Context, client databroker.DataBrokerServiceClient) error {
	ctx = log.WithContext(ctx, func(c zerolog.Context) zerolog.Context {
		return c.Str("service", "zero-analytics")
	})

	return sessions.Collect(ctx, client, time.Hour)
}

// those metrics are cluster-wide, so we only enable their reporting when we have the lease
func (c *controller) enableSessionAnalyticsReporting(ctx context.Context, _ databroker.DataBrokerServiceClient) error {
	_ = c.telemetryReporter.SetMetricProducerEnabled(producerSessionAnalytics, true)
	defer func() { _ = c.telemetryReporter.SetMetricProducerEnabled(producerSessionAnalytics, false) }()

	<-ctx.Done()
	return nil
}

func (c *controller) runHealthChecksLeased(ctx context.Context, client databroker.DataBrokerServiceClient) error {
	ctx = log.WithContext(ctx, func(c zerolog.Context) zerolog.Context {
		return c.Str("service", "zero-health-checks")
	})

	return healthcheck.RunChecks(ctx, c.bootstrapConfig, client)
}

func (c *controller) runTelemetryReporter(ctx context.Context) error {
	health.SetProvider(c.telemetryReporter)
	defer health.SetProvider(nil)

	ctx = log.WithContext(ctx, func(c zerolog.Context) zerolog.Context {
		return c.Str("service", "zero-bootstrap")
	})

	return c.telemetryReporter.Run(ctx)
}
