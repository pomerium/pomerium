// Package controller implements Pomerium managed mode
package controller

import (
	"context"
	"errors"
	"fmt"

	"github.com/rs/zerolog"
	"golang.org/x/sync/errgroup"

	"github.com/pomerium/pomerium/internal/log"
	sdk "github.com/pomerium/pomerium/internal/zero/api"
	"github.com/pomerium/pomerium/internal/zero/bootstrap"
	"github.com/pomerium/pomerium/internal/zero/bootstrap/writers"
	"github.com/pomerium/pomerium/internal/zero/leaser"
	"github.com/pomerium/pomerium/internal/zero/reconciler"
	"github.com/pomerium/pomerium/internal/zero/telemetry/reporter"
	"github.com/pomerium/pomerium/pkg/cmd/pomerium"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

// Run runs Pomerium is managed mode using the provided token.
func Run(ctx context.Context, opts ...Option) error {
	c := controller{cfg: newControllerConfig(opts...)}
	eg, ctx := errgroup.WithContext(ctx)

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

	eg.Go(func() error { return run(ctx, "connect", c.runConnect) })
	eg.Go(func() error { return run(ctx, "connect-log", c.RunConnectLog) })
	eg.Go(func() error { return run(ctx, "zero-bootstrap", c.runBootstrap) })
	eg.Go(func() error { return run(ctx, "pomerium-core", c.runPomeriumCore) })
	eg.Go(func() error { return run(ctx, "zero-control-loop", c.runZeroControlLoop) })
	eg.Go(func() error { return run(ctx, "telemetry-reporter", c.runTelemetryReporter) })
	return eg.Wait()
}

type controller struct {
	cfg *controllerConfig

	api *sdk.API

	bootstrapConfig   *bootstrap.Source
	telemetryReporter *reporter.Reporter
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
	_ = c.initTelemetry(ctx, nil) // temp
	return nil
}

func run(ctx context.Context, name string, runFn func(context.Context) error) error {
	log.Ctx(ctx).Debug().Str("name", name).Msg("starting")
	err := runFn(ctx)
	if err != nil && !errors.Is(err, context.Canceled) {
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
	return leaser.Run(ctx, c.bootstrapConfig,
		c.runReconcilerLeased,
		c.runSessionAnalyticsLeased,
		c.enableSessionAnalyticsReporting,
		c.runHealthChecksLeased,
	)
}

func (c *controller) runReconcilerLeased(ctx context.Context, client databroker.DataBrokerServiceClient) error {
	ctx = log.WithContext(ctx, func(c zerolog.Context) zerolog.Context {
		return c.Str("service", "zero-reconciler")
	})

	return reconciler.Run(ctx,
		reconciler.WithAPI(c.api),
		reconciler.WithDataBrokerClient(client),
	)
}
