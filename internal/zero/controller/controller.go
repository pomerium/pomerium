// Package controller implements Pomerium managed mode
package controller

import (
	"context"
	"errors"
	"fmt"

	"golang.org/x/sync/errgroup"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/zero/bootstrap"
	"github.com/pomerium/pomerium/pkg/cmd/pomerium"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	cluster_api "github.com/pomerium/zero-sdk/cluster"
	connect_mux "github.com/pomerium/zero-sdk/connect-mux"
)

// Run runs Pomerium is managed mode using the provided token.
func Run(ctx context.Context, opts ...Option) error {
	c := controller{cfg: newControllerConfig(opts...)}
	err := c.InitAPI(ctx)
	if err != nil {
		return fmt.Errorf("error initializing cloud api: %w", err)
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

	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(func() error { return run(ctx, "zero-bootstrap", c.runBootstrap, nil) })
	eg.Go(func() error { return run(ctx, "pomerium-core", c.runPomeriumCore, src.WaitReady) })
	eg.Go(func() error { return run(ctx, "zero-reconciler", c.RunReconciler, src.WaitReady) })
	eg.Go(func() error { return run(ctx, "connect-log", c.RunConnectLog, nil) })
	return eg.Wait()
}

type controller struct {
	cfg *controllerConfig

	connectMux    *connect_mux.Mux
	clusterClient cluster_api.ClientWithResponsesInterface

	bootstrapConfig *bootstrap.Source

	databrokerClient databroker.DataBrokerServiceClient
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
	return c.bootstrapConfig.Run(ctx, c.clusterClient, c.connectMux, c.cfg.bootstrapConfigFileName)
}

func (c *controller) runPomeriumCore(ctx context.Context) error {
	return pomerium.Run(ctx, c.bootstrapConfig)
}
