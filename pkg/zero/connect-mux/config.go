package mux

import "context"

type config struct {
	onConnected              func(ctx context.Context)
	onDisconnected           func(ctx context.Context)
	onBundleUpdated          func(ctx context.Context, key string)
	onBootstrapConfigUpdated func(ctx context.Context)
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

func newConfig(opts ...WatchOption) *config {
	cfg := &config{}
	for _, opt := range []WatchOption{
		WithOnConnected(func(_ context.Context) {}),
		WithOnDisconnected(func(_ context.Context) {}),
		WithOnBundleUpdated(func(_ context.Context, key string) {}),
		WithOnBootstrapConfigUpdated(func(_ context.Context) {}),
	} {
		opt(cfg)
	}
	for _, opt := range opts {
		opt(cfg)
	}
	return cfg
}
