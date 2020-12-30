package metrics

import (
	"testing"

	redis "github.com/go-redis/redis/v8"
	"go.opencensus.io/metric/metricdata"
)

func Test_AddRedisMetrics(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		stat redis.PoolStats
		want int64
	}{
		{"redis_conns", redis.PoolStats{TotalConns: 7}, 7},
		{"redis_idle_conns", redis.PoolStats{IdleConns: 3}, 3},
		{"redis_miss_count_total", redis.PoolStats{Misses: 2}, 2},
	}

	labelValues := []metricdata.LabelValue{
		metricdata.NewLabelValue("redis"),
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			AddRedisMetrics(func() *redis.PoolStats { return &tt.stat })
			testMetricRetrieval(registry.registry.Read(), t, labelValues, tt.want, tt.name)
		})
	}
}
