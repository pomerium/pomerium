package metrics

import (
	"github.com/gomodule/redigo/redis"
)

// AddRedisMetrics registers a metrics handler against a redis Client's PoolStats() method
func AddRedisMetrics(stats func() redis.PoolStats) {
	gaugeMetrics := []struct {
		name string
		desc string
		f    func() int64
	}{
		{"redis_conns", "Number of total connections in the pool", func() int64 { return int64(stats().ActiveCount) }},
		{"redis_idle_conns", "Number of idle connections in the pool", func() int64 { return int64(stats().IdleCount) }},
	}

	for _, m := range gaugeMetrics {
		registry.addInt64DerivedGaugeMetric(m.name, m.desc, "redis", m.f)
	}

	cumulativeMetrics := []struct {
		name string
		desc string
		f    func() int64
	}{
		{"redis_wait_count_total", "Total number of connections waited for", func() int64 { return stats().WaitCount }},
		{"redis_wait_duration_ms_total", "Total time spent waiting for connections", func() int64 { return stats().WaitDuration.Milliseconds() }},
	}

	for _, m := range cumulativeMetrics {
		registry.addInt64DerivedCumulativeMetric(m.name, m.desc, "redis", m.f)
	}
}
