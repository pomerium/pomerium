package resolver

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/pomerium/pomerium/pkg/secrets/provider"
)

// resolverMetrics holds the OTel instruments from §1.7. No instrument ever
// receives a secret value: attributes are provider scheme, binding metric
// label, outcome, and state only.
type resolverMetrics struct {
	fetches               metric.Int64Counter
	fetchDuration         metric.Int64Histogram
	servingStale          metric.Int64Counter
	negativeCacheHits     metric.Int64Counter
	singleflightCollapsed metric.Int64Counter

	// observable gauges, kept referenced so the callbacks stay registered
	refsRegistered metric.Int64ObservableGauge
	cacheState     metric.Int64ObservableGauge
}

func newResolverMetrics(meter metric.Meter, r *Resolver) *resolverMetrics {
	m := &resolverMetrics{
		fetches:               mustInt64Counter(meter, "secrets.fetches"),
		fetchDuration:         mustInt64Histogram(meter, "secrets.fetch.duration", metric.WithUnit("ms")),
		servingStale:          mustInt64Counter(meter, "secrets.serving_stale"),
		negativeCacheHits:     mustInt64Counter(meter, "secrets.negative_cache_hits"),
		singleflightCollapsed: mustInt64Counter(meter, "secrets.singleflight_collapsed"),
	}

	var err error
	m.refsRegistered, err = meter.Int64ObservableGauge("secrets.refs_registered",
		metric.WithInt64Callback(func(_ context.Context, o metric.Int64Observer) error {
			counts := map[string]int64{}
			for _, bi := range r.snap.Load().bindings {
				counts[bi.scheme]++
			}
			for scheme, n := range counts {
				o.Observe(n, metric.WithAttributes(attribute.String("provider", scheme)))
			}
			return nil
		}))
	if err != nil {
		panic(err)
	}

	m.cacheState, err = meter.Int64ObservableGauge("secrets.cache_state",
		metric.WithInt64Callback(func(_ context.Context, o metric.Int64Observer) error {
			snap := r.snap.Load()
			for _, bi := range snap.bindings {
				state := StateFailed
				if ve, ok := snap.values[bi.valueKey]; ok {
					state = ve.state
				}
				o.Observe(1, metric.WithAttributes(
					attribute.String("ref_label", bi.metricLabel),
					attribute.String("state", state.String()),
				))
			}
			return nil
		}))
	if err != nil {
		panic(err)
	}

	return m
}

func (r *Resolver) recordFetchMetrics(fs *fetchState, err error, dur time.Duration) {
	outcome := "success"
	switch {
	case err == nil:
	case provider.IsNotFound(err):
		outcome = "not_found"
	default:
		outcome = "error"
	}
	attrs := metric.WithAttributes(
		attribute.String("provider", fs.schemeLabel),
		attribute.String("outcome", outcome),
	)
	r.metrics.fetches.Add(context.Background(), 1, attrs)
	r.metrics.fetchDuration.Record(context.Background(), dur.Milliseconds(), attrs)
}

func (r *Resolver) recordServingStale(vs *valueState) {
	r.metrics.servingStale.Add(context.Background(), 1,
		metric.WithAttributes(attribute.String("ref_label", vs.metricLabel)))
}

func (r *Resolver) recordSingleflightCollapsed(fs *fetchState) {
	r.metrics.singleflightCollapsed.Add(context.Background(), 1,
		metric.WithAttributes(attribute.String("provider", fs.schemeLabel)))
}

func (r *Resolver) recordNegativeCacheHit(fs *fetchState) {
	r.mu.Lock()
	labels := make([]string, 0, len(fs.values))
	for _, vs := range fs.values {
		labels = append(labels, vs.metricLabel)
	}
	r.mu.Unlock()
	for _, label := range labels {
		r.metrics.negativeCacheHits.Add(context.Background(), 1,
			metric.WithAttributes(attribute.String("ref_label", label)))
	}
}

func mustInt64Counter(meter metric.Meter, name string, opts ...metric.Int64CounterOption) metric.Int64Counter {
	c, err := meter.Int64Counter(name, opts...)
	if err != nil {
		panic(err)
	}
	return c
}

func mustInt64Histogram(meter metric.Meter, name string, opts ...metric.Int64HistogramOption) metric.Int64Histogram {
	h, err := meter.Int64Histogram(name, opts...)
	if err != nil {
		panic(err)
	}
	return h
}
