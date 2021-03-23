package metrics

import (
	redis "github.com/go-redis/redis/v8"
)

// AddRedisMetrics registers a metrics handler against a redis Client's PoolStats() method
func AddRedisMetrics(installationID string, stats func() *redis.PoolStats) {
	gaugeMetrics := []struct {
		name string
		desc string
		f    func() int64
	}{
		{"redis_conns", "Number of total connections in the pool", func() int64 { return int64(stats().TotalConns) }},
		{"redis_idle_conns", "Number of idle connections in the pool", func() int64 { return int64(stats().IdleConns) }},
		{"redis_stale_conns", "Number of stale connections in the pool", func() int64 { return int64(stats().StaleConns) }},
	}

	for _, m := range gaugeMetrics {
		registry.addInt64DerivedGaugeMetric(m.name, m.desc, installationID, "redis", m.f)
	}

	cumulativeMetrics := []struct {
		name string
		desc string
		f    func() int64
	}{
		{"redis_miss_count_total", "Total number of times a connection was not found in the pool", func() int64 { return int64(stats().Misses) }},
		{"redis_hit_count_total", "Total number of times a connection was found in the pool", func() int64 { return int64(stats().Hits) }},
	}

	for _, m := range cumulativeMetrics {
		registry.addInt64DerivedCumulativeMetric(m.name, m.desc, installationID, "redis", m.f)
	}
}
