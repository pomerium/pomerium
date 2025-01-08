// Package controller implements Pomerium managed mode
package controller

import (
	"context"
	"fmt"
	"time"

	"github.com/rs/zerolog"
	"golang.org/x/sync/errgroup"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/retry"
	sdk "github.com/pomerium/pomerium/internal/zero/api"
	"github.com/pomerium/pomerium/internal/zero/bootstrap"
	"github.com/pomerium/pomerium/internal/zero/bootstrap/writers"
	connect_mux "github.com/pomerium/pomerium/internal/zero/connect-mux"
	"github.com/pomerium/pomerium/internal/zero/controller/usagereporter"
	"github.com/pomerium/pomerium/internal/zero/healthcheck"
	"github.com/pomerium/pomerium/internal/zero/reconciler"
	"github.com/pomerium/pomerium/internal/zero/telemetry"
	"github.com/pomerium/pomerium/internal/zero/telemetry/sessions"
	"github.com/pomerium/pomerium/pkg/cmd/pomerium"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

// Run runs Pomerium is managed mode using the provided token.
func Run(ctx context.Context, opts ...Option) error {
	c := controller{cfg: newControllerConfig(opts...)}

	err := c.initAPI(ctx)
	if err != nil {
		return fmt.Errorf("init api: %w", err)
	}

	var writer writers.ConfigWriter
	if c.cfg.bootstrapConfigFileName != nil {
		var err error
		var uri string
		if c.cfg.bootstrapConfigWritebackURI != nil {
			// if there is an explicitly configured writeback URI, use it
			uri = *c.cfg.bootstrapConfigWritebackURI
		} else {
			// otherwise, default to "file://<filename>"
			uri = "file://" + *c.cfg.bootstrapConfigFileName
		}
		writer, err = writers.NewForURI(uri)
		if err != nil {
			return fmt.Errorf("error creating bootstrap config writer: %w", err)
		}
	}

	src, err := bootstrap.New([]byte(c.cfg.apiToken), c.cfg.bootstrapConfigFileName, writer, c.api)
	if err != nil {
		return fmt.Errorf("error creating bootstrap config: %w", err)
	}
	c.bootstrapConfig = src

	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(func() error { return run(ctx, "connect", c.runConnect) })
	eg.Go(func() error { return run(ctx, "connect-log", c.RunConnectLog) })
	eg.Go(func() error { return run(ctx, "zero-bootstrap", c.runBootstrap) })
	eg.Go(func() error { return run(ctx, "pomerium-core", c.runPomeriumCore) })
	eg.Go(func() error { return run(ctx, "zero-control-loop", c.runZeroControlLoop) })
	eg.Go(func() error {
		<-ctx.Done()
		log.Ctx(ctx).Info().Msgf("shutting down: %v", context.Cause(ctx))
		return nil
	})
	return eg.Wait()
}

type controller struct {
	cfg *controllerConfig

	api *sdk.API

	bootstrapConfig *bootstrap.Source
}

func (c *controller) initAPI(ctx context.Context) error {
	api, err := sdk.NewAPI(ctx,
		sdk.WithClusterAPIEndpoint(c.cfg.clusterAPIEndpoint),
		sdk.WithAPIToken(c.cfg.apiToken),
		sdk.WithConnectAPIEndpoint(c.cfg.connectAPIEndpoint),
		sdk.WithOTELEndpoint(c.cfg.otelEndpoint),
	)
	if err != nil {
		return fmt.Errorf("error initializing cloud api: %w", err)
	}

	c.api = api
	return nil
}

func run(ctx context.Context, name string, runFn func(context.Context) error) error {
	log.Ctx(ctx).Debug().Str("name", name).Msg("starting")
	defer log.Ctx(ctx).Debug().Str("name", name).Msg("stopped")
	err := runFn(ctx)
	if err != nil && ctx.Err() == nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

func (c *controller) runBootstrap(ctx context.Context) error {
	ctx = log.WithContext(ctx, func(c zerolog.Context) zerolog.Context {
		return c.Str("service", "zero-bootstrap")
	})
	return c.bootstrapConfig.Run(ctx)
}

func (c *controller) runPomeriumCore(ctx context.Context) error {
	err := c.bootstrapConfig.WaitReady(ctx)
	if err != nil {
		return fmt.Errorf("waiting for config source to be ready: %w", err)
	}
	return pomerium.Run(ctx, c.bootstrapConfig)
}

func (c *controller) runConnect(ctx context.Context) error {
	ctx = log.WithContext(ctx, func(c zerolog.Context) zerolog.Context {
		return c.Str("service", "zero-connect")
	})

	return c.api.Connect(ctx)
}

func (c *controller) runZeroControlLoop(ctx context.Context) error {
	ctx = log.WithContext(ctx, func(c zerolog.Context) zerolog.Context {
		return c.Str("control-group", "zero-cluster")
	})

	err := c.bootstrapConfig.WaitReady(ctx)
	if err != nil {
		return fmt.Errorf("waiting for config source to be ready: %w", err)
	}

	r := NewDatabrokerRestartRunner(ctx, c.bootstrapConfig)
	defer r.Close()

	var leaseStatus LeaseStatus
	tm, err := telemetry.New(ctx, c.api,
		r.GetDatabrokerClient,
		leaseStatus.HasLease,
		"/envoy/stats/prometheus",
	)
	if err != nil {
		return fmt.Errorf("init telemetry: %w", err)
	}
	defer c.shutdownWithTimeout(ctx, "telemetry", tm.Shutdown)

	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(func() error { return tm.Run(ctx) })
	eg.Go(func() error {
		return r.Run(ctx,
			WithLease(
				c.runReconcilerLeased,
				c.runSessionAnalyticsLeased,
				c.runHealthChecksLeased,
				leaseStatus.MonitorLease,
				c.runUsageReporter,
			),
		)
	})
	return eg.Wait()
}

func (c *controller) shutdownWithTimeout(ctx context.Context, name string, fn func(context.Context) error) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), c.cfg.shutdownTimeout)
	defer cancel()

	log.Ctx(ctx).Debug().Str("timeout", c.cfg.shutdownTimeout.String()).Msgf("shutting down %s ...", name)
	err := fn(ctx)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msgf("error shutting down %s", name)
	} else {
		log.Ctx(ctx).Debug().Msgf("%s shutdown complete", name)
	}
}

func (c *controller) runReconcilerLeased(ctx context.Context, client databroker.DataBrokerServiceClient) error {
	return retry.WithBackoff(ctx, "zero-reconciler", func(ctx context.Context) error {
		return reconciler.Run(ctx,
			reconciler.WithAPI(c.api),
			reconciler.WithDataBrokerClient(client),
		)
	})
}

func (c *controller) runSessionAnalyticsLeased(ctx context.Context, client databroker.DataBrokerServiceClient) error {
	return retry.WithBackoff(ctx, "zero-analytics", func(ctx context.Context) error {
		return sessions.Collect(ctx, client, time.Hour)
	})
}

func (c *controller) runHealthChecksLeased(ctx context.Context, client databroker.DataBrokerServiceClient) error {
	return retry.WithBackoff(ctx, "zero-healthcheck", func(ctx context.Context) error {
		checker := healthcheck.NewChecker(c.bootstrapConfig, client)
		eg, ctx := errgroup.WithContext(ctx)
		eg.Go(func() error { return checker.Run(ctx) })
		eg.Go(func() error {
			return c.api.Watch(ctx, connect_mux.WithOnRunHealthChecks(func(_ context.Context) {
				checker.ForceCheck()
			}))
		})
		return eg.Wait()
	})
}

func (c *controller) runUsageReporter(ctx context.Context, client databroker.DataBrokerServiceClient) error {
	ur := usagereporter.New(c.api, c.bootstrapConfig.GetConfig().ZeroPseudonymizationKey, time.Minute)
	return retry.WithBackoff(ctx, "zero-usage-reporter", func(ctx context.Context) error {
		// start the usage reporter
		return ur.Run(ctx, client)
	})
}
