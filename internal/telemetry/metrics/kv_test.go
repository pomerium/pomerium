package metrics

import (
	"testing"
	"time"

	"github.com/go-redis/redis/v7"
	"github.com/golang/groupcache"
	"go.etcd.io/bbolt"
	"go.opencensus.io/metric/metricdata"
)

func Test_AddGroupCacheMetrics(t *testing.T) {
	gc := &groupcache.Group{}
	AddGroupCacheMetrics(gc)

	tests := []struct {
		name string
		stat *groupcache.AtomicInt
		want int64
	}{
		{"groupcache_gets_total", &gc.Stats.Gets, 4},
		{"groupcache_loads_total", &gc.Stats.Loads, 42},
		{"groupcache_server_requests_total", &gc.Stats.ServerRequests, 8},
	}

	labelValues := []metricdata.LabelValue{
		metricdata.NewLabelValue("autocache"),
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.stat.Add(tt.want)
			testMetricRetrieval(registry.registry.Read(), t, labelValues, tt.want, tt.name)
		})
	}

}

func Test_AddBoltDBMetrics(t *testing.T) {
	tests := []struct {
		name string
		stat bbolt.Stats
		want int64
	}{
		{"boltdb_free_page_n", bbolt.Stats{FreePageN: 14}, 14},
		{"boltdb_txn", bbolt.Stats{TxN: 88}, 88},

		{"boltdb_txn_rebalance_duration_ms_total", bbolt.Stats{TxStats: bbolt.TxStats{RebalanceTime: 42 * time.Millisecond}}, 42},
		{"boltdb_txn_write_total", bbolt.Stats{TxStats: bbolt.TxStats{Write: 42}}, 42},
	}

	labelValues := []metricdata.LabelValue{
		metricdata.NewLabelValue("boltdb"),
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			AddBoltDBMetrics(func() bbolt.Stats { return tt.stat })
			testMetricRetrieval(registry.registry.Read(), t, labelValues, tt.want, tt.name)
		})
	}

}

func Test_AddRedisMetrics(t *testing.T) {
	tests := []struct {
		name string
		stat *redis.PoolStats
		want int64
	}{
		{"redis_conns", &redis.PoolStats{TotalConns: 7}, 7},
		{"redis_hits_total", &redis.PoolStats{Hits: 78}, 78},
		{"redis_timeouts_total", &redis.PoolStats{Timeouts: 2}, 2},
	}

	labelValues := []metricdata.LabelValue{
		metricdata.NewLabelValue("redis"),
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			AddRedisMetrics(func() *redis.PoolStats { return tt.stat })
			testMetricRetrieval(registry.registry.Read(), t, labelValues, tt.want, tt.name)
		})
	}

}
