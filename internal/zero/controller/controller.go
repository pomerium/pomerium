// Package controller implements Pomerium managed mode
package controller

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/rs/zerolog"
	"golang.org/x/sync/errgroup"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/zero/analytics"
	sdk "github.com/pomerium/pomerium/internal/zero/api"
	"github.com/pomerium/pomerium/internal/zero/bootstrap"
	"github.com/pomerium/pomerium/internal/zero/leaser"
	"github.com/pomerium/pomerium/internal/zero/reconciler"
	"github.com/pomerium/pomerium/internal/zero/reporter"
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

	src, err := bootstrap.New([]byte(c.cfg.apiToken), c.cfg.bootstrapConfigFileName, c.api)
	if err != nil {
		return fmt.Errorf("error creating bootstrap config: %w", err)
	}
	c.bootstrapConfig = src

	eg.Go(func() error { return run(ctx, "connect", c.runConnect) })
	eg.Go(func() error { return run(ctx, "connect-log", c.RunConnectLog) })
	eg.Go(func() error { return run(ctx, "zero-bootstrap", c.runBootstrap) })
	eg.Go(func() error { return run(ctx, "pomerium-core", c.runPomeriumCore) })
	eg.Go(func() error { return run(ctx, "zero-control-loop", c.runZeroControlLoop) })
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
		c.runReconciler,
		c.runAnalytics,
		c.runReporter,
	)
}

func (c *controller) runReconciler(ctx context.Context, client databroker.DataBrokerServiceClient) error {
	ctx = log.WithContext(ctx, func(c zerolog.Context) zerolog.Context {
		return c.Str("service", "zero-reconciler")
	})

	return reconciler.Run(ctx,
		reconciler.WithAPI(c.api),
		reconciler.WithDataBrokerClient(client),
	)
}

func (c *controller) runAnalytics(ctx context.Context, client databroker.DataBrokerServiceClient) error {
	ctx = log.WithContext(ctx, func(c zerolog.Context) zerolog.Context {
		return c.Str("service", "zero-analytics")
	})

	err := analytics.Collect(ctx, client, time.Hour)
	if err != nil && ctx.Err() == nil {
		log.Ctx(ctx).Error().Err(err).Msg("error collecting analytics, disabling")
		return nil
	}

	return err
}

func (c *controller) runReporter(ctx context.Context, client databroker.DataBrokerServiceClient) error {
	ctx = log.WithContext(ctx, func(c zerolog.Context) zerolog.Context {
		return c.Str("service", "zero-reporter")
	})

	return c.api.Report(ctx,
		reporter.WithCollectInterval(time.Hour),
		reporter.WithMetrics(analytics.Metrics(func() databroker.DataBrokerServiceClient { return client })...),
	)
}
