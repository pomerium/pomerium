package pomerium

import (
	"context"
	"net/http"
	"sync"

	"github.com/pomerium/pomerium/config"
)

// swappableConfigSource is used to make swapping the http DefaultTransport
// replaceable without a data race. The DefaultTransport is set to the
// config source Transport in an init, but it can be swapped at runtime with
// a new config source.
type swappableConfigSource struct {
	mu        sync.RWMutex
	current   config.Source
	listeners []config.ChangeListener
}

func (source *swappableConfigSource) GetConfig() *config.Config {
	source.mu.RLock()
	defer source.mu.RUnlock()

	return source.current.GetConfig()
}

func (source *swappableConfigSource) OnConfigChange(_ context.Context, li config.ChangeListener) {
	source.mu.Lock()
	defer source.mu.Unlock()

	source.listeners = append(source.listeners, li)
}

func (source *swappableConfigSource) Swap(ctx context.Context, next config.Source) {
	source.mu.Lock()
	defer source.mu.Unlock()

	source.current = next

	// attach a listener to the new source
	next.OnConfigChange(ctx, func(ctx context.Context, cfg *config.Config) {
		source.mu.RLock()
		defer source.mu.RUnlock()

		if source.current != next {
			return
		}

		for _, li := range source.listeners {
			li(ctx, cfg)
		}
	})

	// call any existing listeners
	for _, li := range source.listeners {
		li(ctx, next.GetConfig())
	}
}

var globalConfigSource = &swappableConfigSource{current: config.NewStaticSource(config.New(config.NewDefaultOptions()))}

func init() {
	http.DefaultTransport = config.NewHTTPTransport(globalConfigSource)
}
