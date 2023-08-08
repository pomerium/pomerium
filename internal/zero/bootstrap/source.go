package bootstrap

import (
	"context"
	"sync"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/atomicutil"
	cluster_api "github.com/pomerium/zero-sdk/cluster"
)

var (
	_ = config.Source(new(source))
)

var (
	cmpOpts = []cmp.Option{
		cmpopts.IgnoreUnexported(config.Options{}),
		cmpopts.EquateEmpty(),
	}
)

type source struct {
	cfg atomicutil.Value[*config.Config]

	listenerLock sync.RWMutex
	listeners    []config.ChangeListener

	ready     chan struct{}
	markReady sync.Once
}

func (src *source) WaitReady(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-src.ready:
		return nil
	}
}

// GetConfig implements config.Source
func (src *source) GetConfig() *config.Config {
	return src.cfg.Load()
}

// OnConfigChange implements config.Source
func (src *source) OnConfigChange(_ context.Context, l config.ChangeListener) {
	src.listenerLock.Lock()
	src.listeners = append(src.listeners, l)
	src.listenerLock.Unlock()
}

// UpdateBootstrap updates the underlying configuration options
func (src *source) UpdateBootstrap(ctx context.Context, cfg cluster_api.BootstrapConfig) bool {
	current := src.cfg.Load()
	incoming := current.Clone()
	applyBootstrapConfig(incoming.Options, &cfg)

	if cmp.Equal(incoming.Options, current.Options, cmpOpts...) {
		return false
	}

	src.cfg.Store(incoming)

	src.notifyListeners(ctx, incoming)

	return true
}

// notifyListeners notifies all listeners of a configuration change
func (src *source) notifyListeners(ctx context.Context, cfg *config.Config) {
	src.markReady.Do(func() { close(src.ready) })

	src.listenerLock.RLock()
	listeners := make([]config.ChangeListener, len(src.listeners))
	copy(listeners, src.listeners)
	src.listenerLock.RUnlock()

	for _, l := range listeners {
		l(ctx, cfg)
	}
}

func applyBootstrapConfig(dst *config.Options, src *cluster_api.BootstrapConfig) {
	if src.DatabrokerStorageConnection != nil {
		dst.DataBrokerStorageType = "postgres"
		dst.DataBrokerStorageConnectionString = *src.DatabrokerStorageConnection
	}
}
