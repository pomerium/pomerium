package config

import (
	"context"
	"fmt"
	"sync"

	"github.com/pomerium/pomerium/internal/log"
)

// LayeredSource is an abstraction for a ConfigSource that depends on an underlying config,
// and uses a builder to build the relevant part of the configuration
type LayeredSource struct {
	mx sync.Mutex

	cfg        *Config
	underlying Source
	builder    func(*Config) error

	ChangeDispatcher
}

var _ = Source(&LayeredSource{})

// NewLayeredSource creates a new config source that is watching the underlying source for changes
func NewLayeredSource(ctx context.Context, underlying Source, builder func(*Config) error) (*LayeredSource, error) {
	cfg := underlying.GetConfig().Clone()
	src := LayeredSource{
		cfg:        cfg,
		underlying: underlying,
		builder:    builder,
	}

	if err := builder(cfg); err != nil {
		return nil, fmt.Errorf("build initial config: %w", err)
	}

	underlying.OnConfigChange(ctx, src.onUnderlyingConfigChange)

	return &src, nil
}

func (src *LayeredSource) onUnderlyingConfigChange(ctx context.Context, next *Config) {
	cfg := src.rebuild(ctx, next)
	src.Trigger(ctx, cfg)
}

func (src *LayeredSource) rebuild(ctx context.Context, next *Config) *Config {
	src.mx.Lock()
	defer src.mx.Unlock()

	cfg := next.Clone()
	if err := src.builder(cfg); err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("building config")
		cfg = next
	}
	src.cfg = cfg
	return cfg
}

// GetConfig returns currently stored config
func (src *LayeredSource) GetConfig() *Config {
	src.mx.Lock()
	defer src.mx.Unlock()
	return src.cfg
}
