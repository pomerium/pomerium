package diff_test

import (
	"context"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/config/diff"
)

func mustParseURL(t *testing.T, s string) url.URL {
	t.Helper()
	u, err := url.Parse(s)
	require.NoError(t, err)
	return *u
}

type eventCollector struct {
	mu       sync.Mutex
	batches  [][]diff.RouteEvent
	received chan struct{}
}

func newEventCollector() *eventCollector {
	return &eventCollector{
		received: make(chan struct{}, 100),
	}
}

func (c *eventCollector) callback(events []diff.RouteEvent) {
	c.mu.Lock()
	c.batches = append(c.batches, events)
	c.mu.Unlock()
	c.received <- struct{}{}
}

func (c *eventCollector) waitForBatch(t *testing.T, timeout time.Duration) []diff.RouteEvent {
	t.Helper()
	select {
	case <-c.received:
		c.mu.Lock()
		defer c.mu.Unlock()
		if len(c.batches) == 0 {
			t.Fatal("received signal but no batches")
		}
		batch := c.batches[0]
		c.batches = c.batches[1:]
		return batch
	case <-time.After(timeout):
		t.Fatal("timeout waiting for events")
		return nil
	}
}

func (c *eventCollector) expectNoBatch(t *testing.T, wait time.Duration) {
	t.Helper()
	select {
	case <-c.received:
		t.Fatal("unexpected event batch received")
	case <-time.After(wait):
	}
}

func TestConfigDiffer_EmptyToNonEmpty(t *testing.T) {
	t.Parallel()

	collector := newEventCollector()
	differ := diff.NewConfigDiffer(diff.WithOnRouteEvents(collector.callback))

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go differ.Run(ctx)

	cfg := &config.Config{
		Options: &config.Options{
			Policies: []config.Policy{
				{
					ID:             "route-1",
					From:           "https://app.example.com",
					To:             config.WeightedURLs{{URL: mustParseURL(t, "http://localhost:8080")}},
					UpstreamTunnel: &config.UpstreamTunnel{},
				},
				{
					ID:             "route-2",
					From:           "https://api.example.com",
					To:             config.WeightedURLs{{URL: mustParseURL(t, "http://localhost:9090")}},
					UpstreamTunnel: &config.UpstreamTunnel{},
				},
			},
		},
	}

	differ.OnConfigUpdated(cfg)

	events := collector.waitForBatch(t, time.Second)
	require.Len(t, events, 2)
	for _, e := range events {
		assert.Equal(t, diff.RouteUpserted, e.Kind)
	}
	ids := map[string]bool{events[0].RouteID: true, events[1].RouteID: true}
	assert.True(t, ids["route-1"])
	assert.True(t, ids["route-2"])
}

func TestConfigDiffer_RouteDeleted(t *testing.T) {
	t.Parallel()

	collector := newEventCollector()
	differ := diff.NewConfigDiffer(diff.WithOnRouteEvents(collector.callback))

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go differ.Run(ctx)

	cfg1 := &config.Config{
		Options: &config.Options{
			Policies: []config.Policy{
				{
					ID:             "route-1",
					From:           "https://app.example.com",
					To:             config.WeightedURLs{{URL: mustParseURL(t, "http://localhost:8080")}},
					UpstreamTunnel: &config.UpstreamTunnel{},
				},
				{
					ID:             "route-2",
					From:           "https://api.example.com",
					To:             config.WeightedURLs{{URL: mustParseURL(t, "http://localhost:9090")}},
					UpstreamTunnel: &config.UpstreamTunnel{},
				},
			},
		},
	}

	differ.OnConfigUpdated(cfg1)
	collector.waitForBatch(t, time.Second)

	cfg2 := &config.Config{
		Options: &config.Options{
			Policies: []config.Policy{
				{
					ID:             "route-1",
					From:           "https://app.example.com",
					To:             config.WeightedURLs{{URL: mustParseURL(t, "http://localhost:8080")}},
					UpstreamTunnel: &config.UpstreamTunnel{},
				},
			},
		},
	}

	differ.OnConfigUpdated(cfg2)

	events := collector.waitForBatch(t, time.Second)
	require.Len(t, events, 1)
	assert.Equal(t, diff.RouteDeleted, events[0].Kind)
	assert.Equal(t, "route-2", events[0].RouteID)
}

func TestConfigDiffer_RouteUpdated(t *testing.T) {
	t.Parallel()

	collector := newEventCollector()
	differ := diff.NewConfigDiffer(diff.WithOnRouteEvents(collector.callback))

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go differ.Run(ctx)

	cfg1 := &config.Config{
		Options: &config.Options{
			Policies: []config.Policy{
				{
					ID:             "route-1",
					From:           "https://app.example.com",
					To:             config.WeightedURLs{{URL: mustParseURL(t, "http://localhost:8080")}},
					UpstreamTunnel: &config.UpstreamTunnel{},
				},
			},
		},
	}

	differ.OnConfigUpdated(cfg1)
	collector.waitForBatch(t, time.Second)

	cfg2 := &config.Config{
		Options: &config.Options{
			Policies: []config.Policy{
				{
					ID:             "route-1",
					From:           "https://app.example.com",
					To:             config.WeightedURLs{{URL: mustParseURL(t, "http://localhost:9999")}}, // changed
					UpstreamTunnel: &config.UpstreamTunnel{},
				},
			},
		},
	}

	differ.OnConfigUpdated(cfg2)

	events := collector.waitForBatch(t, time.Second)
	require.Len(t, events, 1)
	assert.Equal(t, diff.RouteUpserted, events[0].Kind)
	assert.Equal(t, "route-1", events[0].RouteID)
}

func TestConfigDiffer_NoChangeNoEvent(t *testing.T) {
	t.Parallel()

	collector := newEventCollector()
	differ := diff.NewConfigDiffer(diff.WithOnRouteEvents(collector.callback))

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go differ.Run(ctx)

	cfg := &config.Config{
		Options: &config.Options{
			Policies: []config.Policy{
				{
					ID:             "route-1",
					From:           "https://app.example.com",
					To:             config.WeightedURLs{{URL: mustParseURL(t, "http://localhost:8080")}},
					UpstreamTunnel: &config.UpstreamTunnel{},
				},
			},
		},
	}

	differ.OnConfigUpdated(cfg)
	collector.waitForBatch(t, time.Second)

	differ.OnConfigUpdated(cfg)
	collector.expectNoBatch(t, 100*time.Millisecond)
}

func TestConfigDiffer_FiltersNonTunnelRoutes(t *testing.T) {
	t.Parallel()

	tunnelFilter := func(p *config.Policy) bool {
		return p.UpstreamTunnel != nil
	}

	collector := newEventCollector()
	differ := diff.NewConfigDiffer(
		diff.WithFilterFunc(tunnelFilter),
		diff.WithOnRouteEvents(collector.callback),
	)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go differ.Run(ctx)

	cfg := &config.Config{
		Options: &config.Options{
			Policies: []config.Policy{
				{
					ID:             "tunnel-route",
					From:           "https://app.example.com",
					To:             config.WeightedURLs{{URL: mustParseURL(t, "http://localhost:8080")}},
					UpstreamTunnel: &config.UpstreamTunnel{},
				},
				{
					ID:   "non-tunnel-route",
					From: "https://web.example.com",
					To:   config.WeightedURLs{{URL: mustParseURL(t, "http://localhost:3000")}},
				},
			},
		},
	}

	differ.OnConfigUpdated(cfg)

	events := collector.waitForBatch(t, time.Second)
	require.Len(t, events, 1)
	assert.Equal(t, "tunnel-route", events[0].RouteID)
}

func TestConfigDiffer_CustomHashFunc(t *testing.T) {
	t.Parallel()

	fromOnlyHash := func(p *config.Policy) uint64 {
		h := uint64(0)
		for _, c := range p.From {
			h = h*31 + uint64(c)
		}
		return h
	}

	collector := newEventCollector()
	differ := diff.NewConfigDiffer(
		diff.WithHashFunc(fromOnlyHash),
		diff.WithOnRouteEvents(collector.callback),
	)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go differ.Run(ctx)

	cfg1 := &config.Config{
		Options: &config.Options{
			Policies: []config.Policy{
				{
					ID:             "route-1",
					From:           "https://app.example.com",
					To:             config.WeightedURLs{{URL: mustParseURL(t, "http://localhost:8080")}},
					UpstreamTunnel: &config.UpstreamTunnel{},
				},
			},
		},
	}

	differ.OnConfigUpdated(cfg1)
	collector.waitForBatch(t, time.Second)

	cfg2 := &config.Config{
		Options: &config.Options{
			Policies: []config.Policy{
				{
					ID:             "route-1",
					From:           "https://app.example.com",
					To:             config.WeightedURLs{{URL: mustParseURL(t, "http://localhost:9999")}},
					UpstreamTunnel: &config.UpstreamTunnel{},
				},
			},
		},
	}

	differ.OnConfigUpdated(cfg2)
	collector.expectNoBatch(t, 100*time.Millisecond)
}

func TestConfigDiffer_CustomFilter(t *testing.T) {
	t.Parallel()

	apiOnlyFilter := func(p *config.Policy) bool {
		return len(p.ID) >= 3 && p.ID[:3] == "api"
	}

	collector := newEventCollector()
	differ := diff.NewConfigDiffer(
		diff.WithFilterFunc(apiOnlyFilter),
		diff.WithOnRouteEvents(collector.callback),
	)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go differ.Run(ctx)

	cfg := &config.Config{
		Options: &config.Options{
			Policies: []config.Policy{
				{
					ID:             "api-route",
					From:           "https://api.example.com",
					To:             config.WeightedURLs{{URL: mustParseURL(t, "http://localhost:8080")}},
					UpstreamTunnel: &config.UpstreamTunnel{},
				},
				{
					ID:             "web-route",
					From:           "https://web.example.com",
					To:             config.WeightedURLs{{URL: mustParseURL(t, "http://localhost:3000")}},
					UpstreamTunnel: &config.UpstreamTunnel{},
				},
			},
		},
	}

	differ.OnConfigUpdated(cfg)

	events := collector.waitForBatch(t, time.Second)
	require.Len(t, events, 1)
	assert.Equal(t, "api-route", events[0].RouteID)
}

func TestConfigDiffer_NonBlocking(t *testing.T) {
	t.Parallel()

	differ := diff.NewConfigDiffer()

	cfg := &config.Config{
		Options: &config.Options{
			Policies: []config.Policy{
				{
					ID:             "route-1",
					From:           "https://app.example.com",
					To:             config.WeightedURLs{{URL: mustParseURL(t, "http://localhost:8080")}},
					UpstreamTunnel: &config.UpstreamTunnel{},
				},
			},
		},
	}

	done := make(chan struct{})
	go func() {
		differ.OnConfigUpdated(cfg)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("OnConfigUpdated blocked")
	}
}

func TestConfigDiffer_CoalescesRapidUpdates(t *testing.T) {
	t.Parallel()

	collector := newEventCollector()
	differ := diff.NewConfigDiffer(diff.WithOnRouteEvents(collector.callback))

	for i := range 10 {
		cfg := &config.Config{
			Options: &config.Options{
				Policies: []config.Policy{
					{
						ID:             "route-1",
						From:           "https://app.example.com",
						To:             config.WeightedURLs{{URL: mustParseURL(t, "http://localhost:"+string(rune('0'+i))+"000")}},
						UpstreamTunnel: &config.UpstreamTunnel{},
					},
				},
			},
		}
		differ.OnConfigUpdated(cfg)
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go differ.Run(ctx)

	events := collector.waitForBatch(t, time.Second)
	require.Len(t, events, 1)
	assert.Equal(t, diff.RouteUpserted, events[0].Kind)

	collector.expectNoBatch(t, 100*time.Millisecond)
}

func TestConfigDiffer_MixedOperations(t *testing.T) {
	t.Parallel()

	collector := newEventCollector()
	differ := diff.NewConfigDiffer(diff.WithOnRouteEvents(collector.callback))

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go differ.Run(ctx)

	cfg1 := &config.Config{
		Options: &config.Options{
			Policies: []config.Policy{
				{
					ID:             "route-1",
					From:           "https://app1.example.com",
					To:             config.WeightedURLs{{URL: mustParseURL(t, "http://localhost:8081")}},
					UpstreamTunnel: &config.UpstreamTunnel{},
				},
				{
					ID:             "route-2",
					From:           "https://app2.example.com",
					To:             config.WeightedURLs{{URL: mustParseURL(t, "http://localhost:8082")}},
					UpstreamTunnel: &config.UpstreamTunnel{},
				},
				{
					ID:             "route-3",
					From:           "https://app3.example.com",
					To:             config.WeightedURLs{{URL: mustParseURL(t, "http://localhost:8083")}},
					UpstreamTunnel: &config.UpstreamTunnel{},
				},
			},
		},
	}

	differ.OnConfigUpdated(cfg1)
	collector.waitForBatch(t, time.Second)

	cfg2 := &config.Config{
		Options: &config.Options{
			Policies: []config.Policy{
				{
					ID:             "route-1",
					From:           "https://app1.example.com",
					To:             config.WeightedURLs{{URL: mustParseURL(t, "http://localhost:8081")}},
					UpstreamTunnel: &config.UpstreamTunnel{},
				},
				{
					ID:             "route-3",
					From:           "https://app3.example.com",
					To:             config.WeightedURLs{{URL: mustParseURL(t, "http://localhost:9999")}}, // updated
					UpstreamTunnel: &config.UpstreamTunnel{},
				},
				{
					ID:             "route-4",
					From:           "https://app4.example.com",
					To:             config.WeightedURLs{{URL: mustParseURL(t, "http://localhost:8084")}},
					UpstreamTunnel: &config.UpstreamTunnel{},
				},
			},
		},
	}

	differ.OnConfigUpdated(cfg2)

	events := collector.waitForBatch(t, time.Second)
	require.Len(t, events, 3)

	byID := make(map[string]diff.RouteEvent)
	for _, e := range events {
		byID[e.RouteID] = e
	}

	assert.Equal(t, diff.RouteDeleted, byID["route-2"].Kind)
	assert.Equal(t, diff.RouteUpserted, byID["route-3"].Kind)
	assert.Equal(t, diff.RouteUpserted, byID["route-4"].Kind)
}

func TestConfigDiffer_NilConfig(t *testing.T) {
	t.Parallel()

	collector := newEventCollector()
	differ := diff.NewConfigDiffer(diff.WithOnRouteEvents(collector.callback))

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go differ.Run(ctx)

	cfg1 := &config.Config{
		Options: &config.Options{
			Policies: []config.Policy{
				{
					ID:             "route-1",
					From:           "https://app.example.com",
					To:             config.WeightedURLs{{URL: mustParseURL(t, "http://localhost:8080")}},
					UpstreamTunnel: &config.UpstreamTunnel{},
				},
			},
		},
	}

	differ.OnConfigUpdated(cfg1)
	collector.waitForBatch(t, time.Second)

	differ.OnConfigUpdated(nil)

	events := collector.waitForBatch(t, time.Second)
	require.Len(t, events, 1)
	assert.Equal(t, diff.RouteDeleted, events[0].Kind)
	assert.Equal(t, "route-1", events[0].RouteID)
}

func TestConfigDiffer_NilOptions(t *testing.T) {
	t.Parallel()

	collector := newEventCollector()
	differ := diff.NewConfigDiffer(diff.WithOnRouteEvents(collector.callback))

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go differ.Run(ctx)

	cfg1 := &config.Config{
		Options: &config.Options{
			Policies: []config.Policy{
				{
					ID:             "route-1",
					From:           "https://app.example.com",
					To:             config.WeightedURLs{{URL: mustParseURL(t, "http://localhost:8080")}},
					UpstreamTunnel: &config.UpstreamTunnel{},
				},
			},
		},
	}

	differ.OnConfigUpdated(cfg1)
	collector.waitForBatch(t, time.Second)

	differ.OnConfigUpdated(&config.Config{Options: nil})

	events := collector.waitForBatch(t, time.Second)
	require.Len(t, events, 1)
	assert.Equal(t, diff.RouteDeleted, events[0].Kind)
	assert.Equal(t, "route-1", events[0].RouteID)
}

func TestConfigDiffer_ContextCancellation(t *testing.T) {
	t.Parallel()

	differ := diff.NewConfigDiffer()
	ctx, cancel := context.WithCancel(t.Context())

	errC := make(chan error, 1)
	go func() {
		errC <- differ.Run(ctx)
	}()

	cancel()

	select {
	case err := <-errC:
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("Run did not exit on context cancellation")
	}
}
