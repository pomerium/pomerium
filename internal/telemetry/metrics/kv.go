package metrics

import (
	"github.com/go-redis/redis/v7"
	"github.com/golang/groupcache"
	"go.etcd.io/bbolt"
)

// AddGroupCacheMetrics registers a metrics handler against a *groupcache.Group
func AddGroupCacheMetrics(gc *groupcache.Group) {

	cumulativeMetrics := []struct {
		name string
		desc string
		f    func() int64
	}{
		{"groupcache_gets_total", "Total get request, including from peers", gc.Stats.Gets.Get},
		{"groupcache_cache_hits_total", "Total cache hits in local or cluster cache", gc.Stats.CacheHits.Get},
		{"groupcache_cache_hits_total", "Total cache hits in local or cluster cache", gc.Stats.CacheHits.Get},
		{"groupcache_peer_loads_total", "Total remote loads or cache hits without error", gc.Stats.PeerLoads.Get},
		{"groupcache_peer_errors_total", "Total errors from peers", gc.Stats.PeerErrors.Get},
		{"groupcache_loads_total", "Total gets without cache hits", gc.Stats.Loads.Get},
		{"groupcache_loads_deduped_total", "gets without cache hits after duplicate suppression", gc.Stats.LoadsDeduped.Get},
		{"groupcache_local_loads_total", "Total good local loads", gc.Stats.LocalLoads.Get},
		{"groupcache_local_load_errs_total", "Total local load errors", gc.Stats.LocalLoadErrs.Get},
		{"groupcache_server_requests_total", "Total gets from peers", gc.Stats.ServerRequests.Get},
	}

	for _, m := range cumulativeMetrics {
		registry.addInt64DerivedCumulativeMetric(m.name, m.desc, "autocache", m.f)
	}
}

// AddBoltDBMetrics registers a metrics handler against a *bbolt.DB
func AddBoltDBMetrics(stats func() bbolt.Stats) {
	gaugeMetrics := []struct {
		name string
		desc string
		f    func() int64
	}{
		{"boltdb_free_page_n", "Number of free pages on the freelist", func() int64 { return int64(stats().FreePageN) }},
		{"boltdb_pending_page_n", "Number of pending pages on the freelist", func() int64 { return int64(stats().PendingPageN) }},
		{"boltdb_free_alloc_size_bytes", "Bytes allocated in free pages", func() int64 { return int64(stats().FreeAlloc) }},
		{"boltdb_freelist_inuse_size_bytes", "Bytes used by the freelist", func() int64 { return int64(stats().FreelistInuse) }},
		{"boltdb_txn", "total number of started read transactions", func() int64 { return int64(stats().TxN) }},
		{"boltdb_open_txn", "number of currently open read transactions", func() int64 { return int64(stats().OpenTxN) }},
	}

	for _, m := range gaugeMetrics {
		registry.addInt64DerivedGaugeMetric(m.name, m.desc, "boltdb", m.f)
	}

	cumulativeMetrics := []struct {
		name string
		desc string
		f    func() int64
	}{
		{"boltdb_txn_page_total", "Total number of page allocations", func() int64 { return int64(stats().TxStats.PageCount) }},
		{"boltdb_txn_page_alloc_size_bytes_total", "Total bytes allocated", func() int64 { return int64(stats().TxStats.PageAlloc) }},
		{"boltdb_txn_cursor_total", "Total number of cursors created", func() int64 { return int64(stats().TxStats.CursorCount) }},
		{"boltdb_txn_node_total", "Total number of node allocations", func() int64 { return int64(stats().TxStats.NodeCount) }},
		{"boltdb_txn_node_deref_total", "Total number of node dereferences", func() int64 { return int64(stats().TxStats.NodeDeref) }},
		{"boltdb_txn_rebalance_total", "Total number of node rebalances", func() int64 { return int64(stats().TxStats.Rebalance) }},
		{"boltdb_txn_rebalance_duration_ms_total", "Total time spent rebalancing", func() int64 { return stats().TxStats.RebalanceTime.Milliseconds() }},
		{"boltdb_txn_split_total", "Total number of nodes split", func() int64 { return int64(stats().TxStats.Split) }},
		{"boltdb_txn_spill_total", "Total number of nodes spilled", func() int64 { return int64(stats().TxStats.Spill) }},
		{"boltdb_txn_spill_duration_ms_total", "Total time spent spilling", func() int64 { return stats().TxStats.SpillTime.Milliseconds() }},
		{"boltdb_txn_write_total", "Total number of writes performed", func() int64 { return int64(stats().TxStats.Write) }},
		{"boltdb_txn_write_duration_ms_total", "Total time spent writing to disk", func() int64 { return stats().TxStats.WriteTime.Milliseconds() }},
	}

	for _, m := range cumulativeMetrics {
		registry.addInt64DerivedCumulativeMetric(m.name, m.desc, "boltdb", m.f)
	}

}

// AddRedisMetrics registers a metrics handler against a redis Client's PoolStats() method
func AddRedisMetrics(stats func() *redis.PoolStats) {
	gaugeMetrics := []struct {
		name string
		desc string
		f    func() int64
	}{
		{"redis_conns", "Number of total connections in the pool", func() int64 { return int64(stats().TotalConns) }},
		{"redis_idle_conns", "Number of idle connections in the pool", func() int64 { return int64(stats().IdleConns) }},
	}

	for _, m := range gaugeMetrics {
		registry.addInt64DerivedGaugeMetric(m.name, m.desc, "redis", m.f)
	}

	cumulativeMetrics := []struct {
		name string
		desc string
		f    func() int64
	}{
		{"redis_hits_total", "Total number of times free connection was found in the pool", func() int64 { return int64(stats().Hits) }},
		{"redis_misses_total", "Total number of times free connection was NOT found in the pool", func() int64 { return int64(stats().Misses) }},
		{"redis_timeouts_total", "Total number of times a wait timeout occurred", func() int64 { return int64(stats().Timeouts) }},
		{"redis_stale_conns_total", "Total number of stale connections removed from the pool", func() int64 { return int64(stats().StaleConns) }},
	}

	for _, m := range cumulativeMetrics {
		registry.addInt64DerivedCumulativeMetric(m.name, m.desc, "redis", m.f)
	}
}
