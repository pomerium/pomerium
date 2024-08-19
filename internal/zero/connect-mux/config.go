package mux

import (
	"context"

	"github.com/pomerium/pomerium/pkg/zero/connect"
)

type config struct {
	onConnected              func(ctx context.Context)
	onDisconnected           func(ctx context.Context)
	onBundleUpdated          func(ctx context.Context, key string)
	onBootstrapConfigUpdated func(ctx context.Context)
	onRunHealthChecks        func(ctx context.Context)
	onTelemetryRequested     func(ctx context.Context, req *connect.TelemetryRequest)
	onDefaultConfigRequested func(ctx context.Context, req *connect.DefaultConfigRequest)
}

// WatchOption allows to specify callbacks for various events
type WatchOption func(*config)

// WithOnConnected sets the callback for when the connection is established
func WithOnConnected(onConnected func(context.Context)) WatchOption {
	return func(cfg *config) {
		cfg.onConnected = onConnected
	}
}

// WithOnDisconnected sets the callback for when the connection is lost
func WithOnDisconnected(onDisconnected func(context.Context)) WatchOption {
	return func(cfg *config) {
		cfg.onDisconnected = onDisconnected
	}
}

// WithOnBundleUpdated sets the callback for when the bundle is updated
func WithOnBundleUpdated(onBundleUpdated func(ctx context.Context, key string)) WatchOption {
	return func(cfg *config) {
		cfg.onBundleUpdated = onBundleUpdated
	}
}

// WithOnBootstrapConfigUpdated sets the callback for when the bootstrap config is updated
func WithOnBootstrapConfigUpdated(onBootstrapConfigUpdated func(context.Context)) WatchOption {
	return func(cfg *config) {
		cfg.onBootstrapConfigUpdated = onBootstrapConfigUpdated
	}
}

// WithOnRunHealthChecks sets the callback for when health checks are run
func WithOnRunHealthChecks(onRunHealthChecks func(context.Context)) WatchOption {
	return func(cfg *config) {
		cfg.onRunHealthChecks = onRunHealthChecks
	}
}

func WithOnTelemetryRequested(onTelemetryRequested func(context.Context, *connect.TelemetryRequest)) WatchOption {
	return func(cfg *config) {
		cfg.onTelemetryRequested = onTelemetryRequested
	}
}

func WithOnDefaultConfigRequested(onDefaultConfigRequested func(context.Context, *connect.DefaultConfigRequest)) WatchOption {
	return func(cfg *config) {
		cfg.onDefaultConfigRequested = onDefaultConfigRequested
	}
}

func newConfig(opts ...WatchOption) *config {
	cfg := &config{}
	for _, opt := range []WatchOption{
		WithOnConnected(func(_ context.Context) {}),
		WithOnDisconnected(func(_ context.Context) {}),
		WithOnBundleUpdated(func(_ context.Context, _ string) {}),
		WithOnBootstrapConfigUpdated(func(_ context.Context) {}),
		WithOnRunHealthChecks(func(_ context.Context) {}),
		WithOnTelemetryRequested(func(_ context.Context, _ *connect.TelemetryRequest) {}),
		WithOnDefaultConfigRequested(func(_ context.Context, _ *connect.DefaultConfigRequest) {}),
	} {
		opt(cfg)
	}
	for _, opt := range opts {
		opt(cfg)
	}
	return cfg
}
