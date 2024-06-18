package reporter

import (
	"go.opentelemetry.io/otel/sdk/metric"
)

type config struct {
	producers []metric.Producer
}

type Option func(*config)

// WithProducer adds a metric producer to the reporter
func WithProducer(p metric.Producer) Option {
	return func(c *config) {
		c.producers = append(c.producers, p)
	}
}

func getConfig(opts ...Option) config {
	var c config
	for _, opt := range opts {
		opt(&c)
	}
	return c
}
