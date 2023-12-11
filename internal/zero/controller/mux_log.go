package controller

import (
	"context"

	"github.com/rs/zerolog"

	"github.com/pomerium/pomerium/internal/log"
	connect_mux "github.com/pomerium/pomerium/pkg/zero/connect-mux"
)

func (c *controller) RunConnectLog(ctx context.Context) error {
	logger := log.Ctx(ctx).With().Str("service", "connect-mux").Logger().Level(zerolog.InfoLevel)

	return c.api.Watch(ctx,
		connect_mux.WithOnConnected(func(ctx context.Context) {
			logger.Info().Msg("connected")
		}),
		connect_mux.WithOnDisconnected(func(ctx context.Context) {
			logger.Info().Msg("disconnected")
		}),
		connect_mux.WithOnBootstrapConfigUpdated(func(ctx context.Context) {
			logger.Info().Msg("bootstrap config updated")
		}),
		connect_mux.WithOnBundleUpdated(func(ctx context.Context, key string) {
			logger.Info().Str("key", key).Msg("bundle updated")
		}),
	)
}
