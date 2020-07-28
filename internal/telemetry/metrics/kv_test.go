package metrics

import (
	"testing"

	"github.com/gomodule/redigo/redis"
	"go.opencensus.io/metric/metricdata"
)

func Test_AddRedisMetrics(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		stat redis.PoolStats
		want int64
	}{
		{"redis_conns", redis.PoolStats{ActiveCount: 7}, 7},
		{"redis_idle_conns", redis.PoolStats{IdleCount: 3}, 3},
		{"redis_wait_count_total", redis.PoolStats{WaitCount: 2}, 2},
	}

	labelValues := []metricdata.LabelValue{
		metricdata.NewLabelValue("redis"),
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			AddRedisMetrics(func() redis.PoolStats { return tt.stat })
			testMetricRetrieval(registry.registry.Read(), t, labelValues, tt.want, tt.name)
		})
	}

}
