package controller

import (
	"context"

	"github.com/rs/zerolog"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/pomerium/pomerium/internal/log"
	connect_mux "github.com/pomerium/pomerium/internal/zero/connect-mux"
	"github.com/pomerium/pomerium/pkg/zero/connect"
)

func (c *controller) RunConnectLog(ctx context.Context) error {
	logger := log.Ctx(ctx).With().Str("service", "connect-mux").Logger().Level(zerolog.InfoLevel)

	return c.api.Watch(ctx,
		connect_mux.WithOnConnected(func(_ context.Context) {
			logger.Debug().Msg("connected")
		}),
		connect_mux.WithOnDisconnected(func(_ context.Context) {
			logger.Debug().Msg("disconnected")
		}),
		connect_mux.WithOnBootstrapConfigUpdated(func(_ context.Context) {
			logger.Debug().Msg("bootstrap config updated")
		}),
		connect_mux.WithOnBundleUpdated(func(_ context.Context, key string) {
			logger.Debug().Str("key", key).Msg("bundle updated")
		}),
		connect_mux.WithOnRunHealthChecks(func(_ context.Context) {
			logger.Debug().Msg("run health checks")
		}),
		connect_mux.WithOnTelemetryRequested(func(_ context.Context, req *connect.TelemetryRequest) {
			data, _ := protojson.Marshal(req)
			logger.Debug().RawJSON("request", data).Msg("telemetry requested")
		}),
	)
}
