package reporter

import (
	"go.opentelemetry.io/otel/sdk/metric"
)

type config struct {
	producers map[string]*metricsProducer
}

// Option is a functional option for configuring the dialhome package.
type Option func(*config)

// WithProducer adds a metric producer to the reporter
func WithProducer(name string, p metric.Producer) Option {
	return func(c *config) {
		if _, ok := c.producers[name]; ok {
			panic("duplicate producer name " + name)
		}
		c.producers[name] = newProducer(name, p)
	}
}

func getConfig(opts ...Option) config {
	c := config{
		producers: make(map[string]*metricsProducer),
	}
	for _, opt := range opts {
		opt(&c)
	}
	return c
}
