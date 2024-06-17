// Package opencensus is a provider of opencensus based telemetry metrics to the zero telemetry system.
package opencensus

import (
	"context"
	"sync/atomic"

	"go.opentelemetry.io/otel/bridge/opencensus"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

type Producer struct {
	producer metric.Producer
	filter   atomic.Value
}

var _ metric.Producer = (*Producer)(nil)

func New() *Producer {
	p := &Producer{
		producer: opencensus.NewMetricProducer(),
	}
	p.SetFilter(nil)
	return p
}

func (p *Producer) Produce(ctx context.Context) ([]metricdata.ScopeMetrics, error) {
	filter := p.loadFilter()
	metrics, err := p.producer.Produce(ctx)
	if err != nil {
		return nil, err
	}
	var out []metricdata.ScopeMetrics
	for _, sm := range metrics {
		var m []metricdata.Metrics
		for _, metric := range sm.Metrics {
			if _, ok := filter[metric.Name]; ok {
				m = append(m, metric)
			}
		}
		if len(m) > 0 {
			out = append(out, metricdata.ScopeMetrics{
				Scope:   sm.Scope,
				Metrics: m,
			})
		}
	}
	return out, nil
}

func (p *Producer) loadFilter() map[string]struct{} {
	filter, _ := p.filter.Load().(map[string]struct{})
	return filter
}

func (p *Producer) SetFilter(names []string) {
	filter := make(map[string]struct{}, len(names))
	for _, name := range names {
		filter[name] = struct{}{}
	}
	p.filter.Store(filter)
}
