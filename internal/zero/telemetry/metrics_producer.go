package telemetry

import (
	"context"
	"sync/atomic"

	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/pomerium/pomerium/internal/log"
)

// metricsProducer is a wrapper around a metric producer that can be enabled or disabled
type metricsProducer[P metric.Producer] struct {
	enabled  atomic.Bool
	name     string
	producer P
}

func newMetricsProducer[P metric.Producer](name string, p P) *metricsProducer[P] {
	return &metricsProducer[P]{
		name:     name,
		producer: p,
	}
}

// Produce wraps the underlying producer's Produce method and logs any errors,
// to prevent the error from blocking the export of other metrics.
// also checks if the producer is enabled before producing metrics
func (p *metricsProducer[P]) Produce(ctx context.Context) ([]metricdata.ScopeMetrics, error) {
	if enabled := p.enabled.Load(); !enabled {
		return nil, nil
	}

	data, err := p.producer.Produce(ctx)
	if err != nil {
		// we do not return the error here, as we do not want to block the export of other metrics
		log.Ctx(ctx).Error().Err(err).Str("producer", p.name).Msg("failed to produce metrics")
		return nil, nil
	}
	return data, nil
}

func (p *metricsProducer[P]) SetEnabled(v bool) {
	p.enabled.Store(v)
}

func (p *metricsProducer[P]) Name() string {
	return p.name
}

func (p *metricsProducer[P]) Producer() P {
	return p.producer
}
