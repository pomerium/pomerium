package controller

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel/sdk/instrumentation"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry/prometheus"
	connect_mux "github.com/pomerium/pomerium/internal/zero/connect-mux"
	"github.com/pomerium/pomerium/internal/zero/healthcheck"
	"github.com/pomerium/pomerium/internal/zero/telemetry/reporter"
	"github.com/pomerium/pomerium/internal/zero/telemetry/sessions"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/health"
	"github.com/pomerium/pomerium/pkg/zero/connect"
)

const (
	producerSessionAnalytics = "session-analytics"
	producerEnvoy            = "envoy"
)

func (c *controller) initTelemetry(ctx context.Context, clientProvider func() (databroker.DataBrokerServiceClient, error)) error {
	startTime := time.Now()

	sessionMetricProducer := sessions.NewProducer(instrumentation.Scope{Name: "cluster"}, clientProvider)
	envoyMetricProducer, err := prometheus.NewProducer(c.buildEnvoyMetricProducerOptions(nil, nil, startTime)...)
	if err != nil {
		return fmt.Errorf("error creating envoy metric producer: %w", err)
	}

	r, err := reporter.New(ctx, c.api.GetTelemetryConn(),
		reporter.WithProducer(producerSessionAnalytics, sessionMetricProducer),
		reporter.WithProducer(producerEnvoy, envoyMetricProducer),
	)
	if err != nil {
		return fmt.Errorf("error creating telemetry metrics reporter: %w", err)
	}

	err = c.api.Watch(ctx, connect_mux.WithOnTelemetryRequested(func(ctx context.Context, req *connect.TelemetryRequest) {
		sessionMetricProducer.SetEnabled(req.GetSessionAnalytics() != nil)

		if envoyMetricRequest := req.GetEnvoyMetrics(); envoyMetricRequest != nil {
			opts := c.buildEnvoyMetricProducerOptions(envoyMetricRequest.GetMetrics(), envoyMetricRequest.GetLabels(), startTime)
			err := envoyMetricProducer.SetConfig(opts...)
			if err != nil {
				log.Warn(ctx).Err(err).Msg("failed to set envoy metric producer options")
			}
		} else {
			_ = envoyMetricProducer.SetConfig(c.buildEnvoyMetricProducerOptions(nil, nil, startTime)...)
		}

		c.telemetryReporter.CollectAndExportMetrics(ctx)
	}))
	if err != nil {
		return fmt.Errorf("watch telemetry: %w", err)
	}

	c.telemetryReporter = r
	return nil
}

func (c *controller) buildEnvoyMetricProducerOptions(metrics, labels []string, startTime time.Time) []prometheus.ProducerOption {
	return []prometheus.ProducerOption{
		prometheus.WithIncludeMetrics(metrics...),
		prometheus.WithIncludeLabels(labels...),
		prometheus.WithScope(instrumentation.Scope{Name: "envoy"}),
		prometheus.WithScrapeURL((&url.URL{
			Scheme: "http",
			Host:   net.JoinHostPort("localhost", c.bootstrapConfig.GetConfig().OutboundPort),
			Path:   "/envoy/stats/prometheus",
		}).String()),
		prometheus.WithStartTime(startTime),
	}
}

func (c *controller) shutdownTelemetry(ctx context.Context) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), c.cfg.shutdownTimeout)
	defer cancel()

	err := c.telemetryReporter.Shutdown(ctx)
	if err != nil {
		log.Warn(ctx).Err(err).Msg("telemetry reporter shutdown error")
	}
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
