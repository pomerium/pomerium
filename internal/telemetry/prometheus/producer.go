package prometheus

import (
	"context"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel/sdk/instrumentation"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

type producerConfig struct {
	client    *http.Client
	scrapeURL string
	scope     instrumentation.Scope
	startTime time.Time
	metrics   map[string]struct{}
	labels    map[string]struct{}
}

type ProducerOption func(*producerConfig)

func WithClient(client *http.Client) ProducerOption {
	return func(cfg *producerConfig) {
		cfg.client = client
	}
}

func WithScope(scope instrumentation.Scope) ProducerOption {
	return func(cfg *producerConfig) {
		cfg.scope = scope
	}
}

func WithStartTime(startTime time.Time) ProducerOption {
	return func(cfg *producerConfig) {
		cfg.startTime = startTime
	}
}

func WithIncludeMetrics(metrics ...string) ProducerOption {
	return func(cfg *producerConfig) {
		if cfg.metrics == nil {
			cfg.metrics = make(map[string]struct{}, len(metrics))
		}
		for _, metric := range metrics {
			cfg.metrics[metric] = struct{}{}
		}
	}
}

func WithIncludeLabels(labels ...string) ProducerOption {
	return func(cfg *producerConfig) {
		if cfg.labels == nil {
			cfg.labels = make(map[string]struct{}, len(labels))
		}
		for _, label := range labels {
			cfg.labels[label] = struct{}{}
		}
	}
}

func WithScrapeURL(scrapeURL string) ProducerOption {
	return func(cfg *producerConfig) {
		cfg.scrapeURL = scrapeURL
	}
}

func newProducerConfig(opts ...ProducerOption) *producerConfig {
	cfg := &producerConfig{
		client: http.DefaultClient,
	}
	for _, opt := range opts {
		opt(cfg)
	}
	return cfg
}

type Producer struct {
	producerConfig atomic.Value
}

func NewProducer(opts ...ProducerOption) *Producer {
	cfg := newProducerConfig(opts...)

	p := new(Producer)
	p.setConfig(cfg)
	return p
}

func (p *Producer) UpdateConfig(opts ...ProducerOption) {
	cfg := *p.loadConfig()
	for _, opt := range opts {
		opt(&cfg)
	}
	p.setConfig(&cfg)
}

func (p *Producer) Produce(ctx context.Context) ([]metricdata.ScopeMetrics, error) {
	cfg := p.loadConfig()

	if len(cfg.metrics) == 0 {
		return nil, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.scrapeURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	resp, err := cfg.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to do request: %w", err)
	}
	defer resp.Body.Close()
	metrics, err := ToOTLP(resp.Body, filter(cfg.metrics), filter(cfg.labels), cfg.startTime, time.Now())
	if err != nil {
		return nil, fmt.Errorf("failed to convert metrics to OTLP: %w", err)
	}
	return []metricdata.ScopeMetrics{
		{
			Scope:   cfg.scope,
			Metrics: metrics,
		},
	}, nil
}

func (p *Producer) setConfig(cfg *producerConfig) {
	p.producerConfig.Store(cfg)
}

func (p *Producer) loadConfig() *producerConfig {
	return p.producerConfig.Load().(*producerConfig)
}

func filter(src map[string]struct{}) func(k string) (string, bool) {
	return func(k string) (string, bool) {
		if len(src) == 0 {
			return k, true
		}
		if _, ok := src[k]; ok {
			return k, true
		}
		return "", false
	}
}
