package telemetry

import (
	"context"
	"fmt"
	"time"

	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel/sdk/instrumentation"
	"golang.org/x/sync/errgroup"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry/prometheus"
	sdk "github.com/pomerium/pomerium/internal/zero/api"
	connect_mux "github.com/pomerium/pomerium/internal/zero/connect-mux"
	"github.com/pomerium/pomerium/internal/zero/telemetry/opencensus"
	"github.com/pomerium/pomerium/internal/zero/telemetry/reporter"
	"github.com/pomerium/pomerium/internal/zero/telemetry/sessions"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/health"
	"github.com/pomerium/pomerium/pkg/zero/connect"
)

type Telemetry struct {
	api      *sdk.API
	reporter *reporter.Reporter

	envoyMetrics           *metricsProducer[*prometheus.Producer]
	sessionMetrics         *metricsProducer[*sessions.Producer]
	coreMetrics            *metricsProducer[*opencensus.Producer]
	hasSessionMetricsLease func() bool
}

func New(
	ctx context.Context,
	api *sdk.API,
	clientProvider func() (databroker.DataBrokerServiceClient, error),
	hasSessionMetricsLease func() bool,
	envoyScrapeURL string,
) (*Telemetry, error) {
	startTime := time.Now()

	sessionMetricProducer := newMetricsProducer("sessions", buildSessionMetricsProducer(clientProvider))
	envoyMetricProducer := newMetricsProducer("envoy", buildEnvoyMetricsProducer(envoyScrapeURL, startTime))
	coreMetricsProducer := newMetricsProducer("core", opencensus.New())

	r, err := reporter.New(ctx, api.GetTelemetryConn(),
		reporter.WithProducer(sessionMetricProducer),
		reporter.WithProducer(envoyMetricProducer),
		reporter.WithProducer(coreMetricsProducer),
	)
	if err != nil {
		return nil, fmt.Errorf("error creating telemetry metrics reporter: %w", err)
	}

	return &Telemetry{
		api:                    api,
		reporter:               r,
		sessionMetrics:         sessionMetricProducer,
		envoyMetrics:           envoyMetricProducer,
		coreMetrics:            coreMetricsProducer,
		hasSessionMetricsLease: hasSessionMetricsLease,
	}, nil
}

func (srv *Telemetry) Shutdown(ctx context.Context) error {
	return srv.reporter.Shutdown(ctx)
}

func (srv *Telemetry) Run(ctx context.Context) error {
	ctx = log.WithContext(ctx, func(c zerolog.Context) zerolog.Context {
		return c.Str("service", "telemetry-reporter")
	})

	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(func() error { return srv.reporter.Run(ctx) })
	eg.Go(func() error { return srv.handleRequests(ctx) })
	eg.Go(func() error {
		healthMgr := health.GetProviderManager()
		healthMgr.Register(health.ProviderMetrics, srv.reporter)
		<-ctx.Done()
		healthMgr.Deregister(health.ProviderMetrics)
		return nil
	})
	return eg.Wait()
}

// handleRequests watches for telemetry requests as they are received from the cloud control plane and processes them.
func (srv *Telemetry) handleRequests(ctx context.Context) error {
	requests := make(chan *connect.TelemetryRequest, 1)

	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(func() error {
		return srv.api.Watch(ctx, connect_mux.WithOnTelemetryRequested(
			func(ctx context.Context, req *connect.TelemetryRequest) {
				select {
				case requests <- req:
				default:
					log.Ctx(ctx).Error().Msg("dropping telemetry request")
				}
			}))
	})
	eg.Go(func() error {
		for {
			select {
			case req := <-requests:
				srv.handleRequest(ctx, req)
			case <-ctx.Done():
				return context.Cause(ctx)
			}
		}
	})
	return eg.Wait()
}

func (srv *Telemetry) handleRequest(ctx context.Context, req *connect.TelemetryRequest) {
	srv.configureEnvoyMetricsProducer(req.GetEnvoyMetrics())
	srv.configureSessionMetricsProducer(req.GetSessionAnalytics())
	srv.configureCoreMetricsProducer(req.GetPomeriumMetrics())

	err := srv.reporter.CollectAndExportMetrics(ctx)
	if err != nil {
		health.ReportError(health.CollectAndSendTelemetry, err)
	} else {
		health.ReportOK(health.CollectAndSendTelemetry)
	}
}

func buildSessionMetricsProducer(clientProvider func() (databroker.DataBrokerServiceClient, error)) *sessions.Producer {
	return sessions.NewProducer(instrumentation.Scope{Name: "pomerium-cluster"}, clientProvider)
}

func buildEnvoyMetricsProducer(scrapeURL string, startTime time.Time) *prometheus.Producer {
	return prometheus.NewProducer(
		prometheus.WithScope(instrumentation.Scope{Name: "envoy"}),
		prometheus.WithScrapeURL(scrapeURL),
		prometheus.WithStartTime(startTime),
	)
}

func (srv *Telemetry) configureSessionMetricsProducer(req *connect.SessionAnalyticsRequest) {
	srv.sessionMetrics.SetEnabled(req != nil && srv.hasSessionMetricsLease())
}

func (srv *Telemetry) configureEnvoyMetricsProducer(req *connect.EnvoyMetricsRequest) {
	if req == nil {
		srv.envoyMetrics.SetEnabled(false)
		return
	}
	srv.envoyMetrics.Producer().UpdateConfig(
		prometheus.WithIncludeMetrics(req.GetMetrics()...),
		prometheus.WithIncludeLabels(req.GetLabels()...),
	)
	srv.envoyMetrics.SetEnabled(true)
}

func (srv *Telemetry) configureCoreMetricsProducer(req *connect.PomeriumMetricsRequest) {
	if req == nil {
		srv.coreMetrics.SetEnabled(false)
		return
	}
	srv.coreMetrics.Producer().SetFilter(req.Metrics)
	srv.coreMetrics.SetEnabled(true)
}
