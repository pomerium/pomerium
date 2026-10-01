package pomerium

import (
	"context"
	"net/http"
	"slices"
	"sync"

	"github.com/pomerium/pomerium/config"
)

// swappableConfigSource is used to make swapping the http DefaultTransport
// replaceable without a data race. The DefaultTransport is set to the
// config source Transport in an init, but it can be swapped at runtime with
// a new config source.
type swappableConfigSource struct {
	mu        sync.Mutex
	current   config.Source
	listeners []config.ChangeListener
}

func (source *swappableConfigSource) GetConfig() *config.Config {
	source.mu.Lock()
	current := source.current
	source.mu.Unlock()

	return current.GetConfig()
}

func (source *swappableConfigSource) OnConfigChange(_ context.Context, li config.ChangeListener) {
	source.mu.Lock()
	defer source.mu.Unlock()

	source.listeners = append(source.listeners, li)
}

func (source *swappableConfigSource) Swap(ctx context.Context, next config.Source) {
	source.mu.Lock()
	source.current = next
	source.mu.Unlock()

	// attach a listener to the new source
	next.OnConfigChange(ctx, func(ctx context.Context, cfg *config.Config) {
		source.dispatch(ctx, next, cfg)
	})

	// call any existing listeners
	source.dispatch(ctx, next, next.GetConfig())
}

// dispatch calls the listeners with cfg if from is still the current source.
func (source *swappableConfigSource) dispatch(ctx context.Context, from config.Source, cfg *config.Config) {
	source.mu.Lock()
	if source.current != from {
		source.mu.Unlock()
		return
	}
	listeners := slices.Clone(source.listeners)
	source.mu.Unlock()

	for _, li := range listeners {
		li(ctx, cfg)
	}
}

var globalConfigSource = &swappableConfigSource{current: config.NewStaticSource(config.New(config.NewDefaultOptions()))}

func init() {
	http.DefaultTransport = config.NewHTTPTransport(globalConfigSource)
}
