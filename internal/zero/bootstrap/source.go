package bootstrap

import (
	"context"
	"sync"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/atomicutil"
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
	return src.cfg.Load().Clone()
}

// OnConfigChange implements config.Source
func (src *source) OnConfigChange(_ context.Context, l config.ChangeListener) {
	src.listenerLock.Lock()
	src.listeners = append(src.listeners, l)
	src.listenerLock.Unlock()
}

// setConfig updates the underlying configuration
// its only called by the updater
func (src *source) SetConfig(ctx context.Context, cfg *config.Config) bool {
	current := src.cfg.Load()
	if cmp.Equal(cfg.Options, current.Options, cmpOpts...) {
		return false
	}

	src.cfg.Store(cfg)
	src.notifyListeners(ctx, cfg)

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
