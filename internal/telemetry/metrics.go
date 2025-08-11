package telemetry

import (
	"sync"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
)

var (
	metricLock sync.RWMutex
	counters   = map[[2]string]metric.Int64Counter{}
	histograms = map[[2]string]metric.Float64Histogram{}
	gauges     = map[[2]string]metric.Int64Gauge{}
)

func getGauge(component, name string) metric.Int64Gauge {
	metricLock.RLock()
	g, ok := gauges[[2]string{component, name}]
	metricLock.RUnlock()
	if ok {
		return g
	}

	metricLock.Lock()
	defer metricLock.Unlock()

	g, ok = gauges[[2]string{component, name}]
	if ok {
		return g
	}

	g, _ = otel.Meter(component).Int64Gauge(component + "." + name)
	gauges[[2]string{component, name}] = g
	return g
}

func getInt64Counter(component, name string) metric.Int64Counter {
	metricLock.RLock()
	c, ok := counters[[2]string{component, name}]
	metricLock.RUnlock()
	if ok {
		return c
	}

	metricLock.Lock()
	defer metricLock.Unlock()

	c, ok = counters[[2]string{component, name}]
	if ok {
		return c
	}

	c, _ = otel.Meter(component).Int64Counter(component + "." + name)
	counters[[2]string{component, name}] = c
	return c
}

func getFloat64Histogram(component, name string, options ...metric.Float64HistogramOption) metric.Float64Histogram {
	metricLock.RLock()
	h, ok := histograms[[2]string{component, name}]
	metricLock.RUnlock()
	if ok {
		return h
	}

	metricLock.Lock()
	defer metricLock.Unlock()

	h, ok = histograms[[2]string{component, name}]
	if ok {
		return h
	}

	h, _ = otel.Meter(component).Float64Histogram(component+"."+name, options...)
	histograms[[2]string{component, name}] = h
	return h
}
