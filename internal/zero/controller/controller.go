// Package controller implements Pomerium managed mode
package controller

import (
	"context"
	"errors"
	"fmt"

	"github.com/rs/zerolog"
	"golang.org/x/sync/errgroup"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/zero/analytics"
	"github.com/pomerium/pomerium/internal/zero/bootstrap"
	"github.com/pomerium/pomerium/internal/zero/reconciler"
	"github.com/pomerium/pomerium/pkg/cmd/pomerium"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	sdk "github.com/pomerium/zero-sdk"
)

// Run runs Pomerium is managed mode using the provided token.
func Run(ctx context.Context, opts ...Option) error {
	c := controller{cfg: newControllerConfig(opts...)}
	eg, ctx := errgroup.WithContext(ctx)

	err := c.initAPI(ctx)
	if err != nil {
		return fmt.Errorf("init api: %w", err)
	}

	src, err := bootstrap.New([]byte(c.cfg.apiToken))
	if err != nil {
		return fmt.Errorf("error creating bootstrap config: %w", err)
	}
	c.bootstrapConfig = src

	err = c.InitDatabrokerClient(ctx, src.GetConfig())
	if err != nil {
		return fmt.Errorf("init databroker client: %w", err)
	}

	eg.Go(func() error { return run(ctx, "connect", c.runConnect, nil) })
	eg.Go(func() error { return run(ctx, "zero-bootstrap", c.runBootstrap, nil) })
	eg.Go(func() error { return run(ctx, "pomerium-core", c.runPomeriumCore, src.WaitReady) })
	eg.Go(func() error { return run(ctx, "zero-reconciler", c.runReconciler, src.WaitReady) })
	eg.Go(func() error { return run(ctx, "connect-log", c.RunConnectLog, nil) })
	eg.Go(func() error { return run(ctx, "zero-analytics", c.runAnalytics(), src.WaitReady) })
	return eg.Wait()
}

type controller struct {
	cfg *controllerConfig

	api *sdk.API

	bootstrapConfig *bootstrap.Source

	databrokerClient databroker.DataBrokerServiceClient
}

func (c *controller) initAPI(ctx context.Context) error {
	api, err := sdk.NewAPI(ctx,
		sdk.WithClusterAPIEndpoint(c.cfg.clusterAPIEndpoint),
		sdk.WithAPIToken(c.cfg.apiToken),
		sdk.WithConnectAPIEndpoint(c.cfg.connectAPIEndpoint),
	)
	if err != nil {
		return fmt.Errorf("error initializing cloud api: %w", err)
	}

	c.api = api

	return nil
}

func run(ctx context.Context, name string, runFn func(context.Context) error, waitFn func(context.Context) error) error {
	if waitFn != nil {
		log.Ctx(ctx).Info().Str("name", name).Msg("waiting for initial configuration")
		err := waitFn(ctx)
		if err != nil {
			return fmt.Errorf("%s: error waiting for initial configuration: %w", name, err)
		}
	}

	log.Ctx(ctx).Info().Str("name", name).Msg("starting")
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
	return c.bootstrapConfig.Run(ctx, c.api, c.cfg.bootstrapConfigFileName)
}

func (c *controller) runPomeriumCore(ctx context.Context) error {
	return pomerium.Run(ctx, c.bootstrapConfig)
}

func (c *controller) runConnect(ctx context.Context) error {
	ctx = log.WithContext(ctx, func(c zerolog.Context) zerolog.Context {
		return c.Str("service", "zero-connect")
	})

	return c.api.Connect(ctx)
}

func (c *controller) runReconciler(ctx context.Context) error {
	ctx = log.WithContext(ctx, func(c zerolog.Context) zerolog.Context {
		return c.Str("service", "zero-reconciler")
	})

	return reconciler.Run(ctx,
		reconciler.WithAPI(c.api),
		reconciler.WithDataBrokerClient(c.GetDataBrokerServiceClient()),
	)
}

func (c *controller) runAnalytics() func(ctx context.Context) error {
	disable := false
	return func(ctx context.Context) error {
		if disable {
			log.Ctx(ctx).Info().Msg("analytics disabled due to previous error")
			<-ctx.Done()
			return nil
		}

		err := analytics.Collect(ctx, c.GetDataBrokerServiceClient())
		if err != nil && ctx.Err() == nil {
			disable = true
			log.Ctx(ctx).Error().Err(err).Msg("error collecting analytics, disabling")
			return nil
		}

		return err
	}
}
