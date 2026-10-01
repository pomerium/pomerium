package pomerium

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/config"
)

func TestSwappableConfigSource(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	newConfig := func(id string) *config.Config {
		opts := config.NewDefaultOptions()
		opts.InstallationID = id
		return config.New(opts)
	}

	cfg0, cfg1, cfg2, cfg3, cfg4 := newConfig("0"), newConfig("1"), newConfig("2"), newConfig("3"), newConfig("4")
	src1, src2 := config.NewStaticSource(cfg1), config.NewStaticSource(cfg2)

	source := &swappableConfigSource{current: config.NewStaticSource(cfg0)}

	var (
		mu  sync.Mutex
		got []*config.Config
	)
	source.OnConfigChange(ctx, func(_ context.Context, cfg *config.Config) {
		mu.Lock()
		got = append(got, cfg)
		mu.Unlock()
	})
	received := func() []*config.Config {
		mu.Lock()
		defer mu.Unlock()
		return got
	}

	assert.Same(t, cfg0, source.GetConfig())

	source.Swap(ctx, src1)
	assert.Same(t, cfg1, source.GetConfig())
	assert.Equal(t, []*config.Config{cfg1}, received(), "listeners should be called with the new config on swap")

	src1.SetConfig(ctx, cfg3)
	assert.Equal(t, []*config.Config{cfg1, cfg3}, received(), "changes to the current source should be forwarded")

	source.Swap(ctx, src2)
	assert.Same(t, cfg2, source.GetConfig())
	assert.Equal(t, []*config.Config{cfg1, cfg3, cfg2}, received())

	src1.SetConfig(ctx, cfg4)
	assert.Equal(t, []*config.Config{cfg1, cfg3, cfg2}, received(), "changes to a previous source should be ignored")
}

func TestSwappableConfigSourceReentrant(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	cfg1 := config.New(config.NewDefaultOptions())
	src := config.NewStaticSource(cfg1)

	source := &swappableConfigSource{current: config.NewStaticSource(config.New(config.NewDefaultOptions()))}

	var got []*config.Config
	source.OnConfigChange(ctx, func(_ context.Context, _ *config.Config) {
		// calling back into the source from a listener must not deadlock
		got = append(got, source.GetConfig())
	})

	done := make(chan struct{})
	go func() {
		defer close(done)
		source.Swap(ctx, src)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("deadlock")
	}
	assert.Equal(t, []*config.Config{cfg1}, got)
}
