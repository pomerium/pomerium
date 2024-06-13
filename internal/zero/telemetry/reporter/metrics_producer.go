package reporter

import (
	"context"
	"sync/atomic"

	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/pomerium/pomerium/internal/log"
)

type metricsProducer struct {
	enabled atomic.Bool
	name    string
	metric.Producer
}

func newProducer(name string, p metric.Producer) *metricsProducer {
	return &metricsProducer{
		name:     name,
		Producer: p,
	}
}

var _ metric.Producer = (*metricsProducer)(nil)

// Produce wraps the underlying producer's Produce method and logs any errors,
// to prevent the error from blocking the export of other metrics.
// also checks if the producer is enabled before producing metrics
func (p *metricsProducer) Produce(ctx context.Context) ([]metricdata.ScopeMetrics, error) {
	if enabled := p.enabled.Load(); !enabled {
		return nil, nil
	}

	data, err := p.Producer.Produce(ctx)
	if err != nil {
		log.Error(ctx).Err(err).Str("producer", p.name).Msg("failed to produce metrics")
		return nil, err
	}
	return data, nil
}

// SetEnabled sets the enabled state of the producer
func (p *metricsProducer) SetEnabled(v bool) {
	p.enabled.Store(v)
}
