package file

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
)

func (backend *Backend) registerMetrics() (metric.Registration, error) {
	m := otel.Meter("")

	blockCacheSize, err := m.Int64ObservableGauge("storage.pebble.block_cache.size",
		metric.WithDescription("The number of bytes inuse by the cache."),
		metric.WithUnit("By"))
	if err != nil {
		return nil, err
	}

	blockCacheCount, err := m.Int64ObservableGauge("storage.pebble.block_cache.count",
		metric.WithDescription("The count of objects (blocks or tables) in the cache."),
		metric.WithUnit("{object}"))
	if err != nil {
		return nil, err
	}

	blockCacheHits, err := m.Int64ObservableGauge("storage.pebble.block_cache.hits",
		metric.WithDescription("The number of cache hits."),
		metric.WithUnit("{hit}"))
	if err != nil {
		return nil, err
	}

	blockCacheMisses, err := m.Int64ObservableGauge("storage.pebble.block_cache.misses",
		metric.WithDescription("The number of cache misses."),
		metric.WithUnit("{miss}"))
	if err != nil {
		return nil, err
	}

	compactionCount, err := m.Int64ObservableGauge("storage.pebble.compactions",
		metric.WithDescription("The total number of compactions, and per-compaction type counts."),
		metric.WithUnit("{compaction}"))
	if err != nil {
		return nil, err
	}

	ingestionCount, err := m.Int64ObservableGauge("storage.pebble.ingestions",
		metric.WithDescription("The total number of ingestions"),
		metric.WithUnit("{ingestion}"))
	if err != nil {
		return nil, err
	}

	flushCount, err := m.Int64ObservableGauge("storage.pebble.flushes",
		metric.WithDescription("The total number of flushes"),
		metric.WithUnit("{flush}"))
	if err != nil {
		return nil, err
	}

	filterHits, err := m.Int64ObservableGauge("storage.pebble.filter.hits",
		metric.WithDescription("The number of hits for the filter policy. This is the number of times the filter policy was successfully used to avoid access of a data block."),
		metric.WithUnit("{hit}"))
	if err != nil {
		return nil, err
	}

	filterMisses, err := m.Int64ObservableGauge("storage.pebble.filter.misses",
		metric.WithDescription("The number of misses for the filter policy. This is the number of times the filter policy was checked but was unable to filter an access of a data block."),
		metric.WithUnit("{miss}"))
	if err != nil {
		return nil, err
	}

	memTableSize, err := m.Int64ObservableGauge("storage.pebble.mem_table.size",
		metric.WithDescription("The number of bytes allocated by memtables and large (flushable) batches."),
		metric.WithUnit("By"))
	if err != nil {
		return nil, err
	}

	memTableCount, err := m.Int64ObservableGauge("storage.pebble.mem_table.count",
		metric.WithDescription("The count of memtables."),
		metric.WithUnit("{mem_table}"))
	if err != nil {
		return nil, err
	}

	snapshotCount, err := m.Int64ObservableGauge("storage.pebble.snapshot.count",
		metric.WithDescription("The number of currently open snapshots."),
		metric.WithUnit("{snapshot}"))
	if err != nil {
		return nil, err
	}

	walFiles, err := m.Int64ObservableGauge("storage.pebble.wal.files",
		metric.WithDescription("Number of live WAL files."),
		metric.WithUnit("{file}"))
	if err != nil {
		return nil, err
	}

	walSize, err := m.Int64ObservableGauge("storage.pebble.wal.size",
		metric.WithDescription("Size of the live data in the WAL files. Note that with WAL file recycling this is less than the actual on-disk size of the WAL files."),
		metric.WithUnit("By"))
	if err != nil {
		return nil, err
	}

	diskSpaceUsage, err := m.Int64ObservableGauge("storage.pebble.disk_space_usage",
		metric.WithDescription("DiskSpaceUsage returns the total disk space used by the database in bytes, including live and obsolete files. This only includes local files, i.e., remote files (as known to objstorage.Provider) are not included."),
		metric.WithUnit("By"))
	if err != nil {
		return nil, err
	}

	virtualSSTables, err := m.Int64ObservableGauge("storage.pebble.virtual_sstables",
		metric.WithDescription("NumVirtual is the number of virtual sstables in the latest version summed over every level in the lsm."),
		metric.WithUnit("{sstable}"))
	if err != nil {
		return nil, err
	}

	virtualSize, err := m.Int64ObservableGauge("storage.pebble.virtual_size",
		metric.WithDescription("VirtualSize is the sum of the sizes of the virtual sstables in the latest version. BackingTableSize - VirtualSize gives an estimate for the space amplification caused by not compacting virtual sstables."),
		metric.WithUnit("By"))
	if err != nil {
		return nil, err
	}

	readAmplification, err := m.Int64ObservableGauge("storage.pebble.read_amplification",
		metric.WithDescription("ReadAmp returns the current read amplification of the database. It's computed as the number of sublevels in L0 + the number of non-empty levels below L0."))
	if err != nil {
		return nil, err
	}

	totalSubLevels, err := m.Int64ObservableGauge("storage.pebble.sublevels",
		metric.WithDescription("The number of sublevels. The sublevel count corresponds to the read amplification for the level. An empty level will have a sublevel count of 0, implying no read amplification. Only L0 will have a sublevel count other than 0 or 1."),
		metric.WithUnit("{sublevel}"))
	if err != nil {
		return nil, err
	}

	totalTableCount, err := m.Int64ObservableGauge("storage.pebble.tables",
		metric.WithDescription("The total count of sstables."),
		metric.WithUnit("{table}"))
	if err != nil {
		return nil, err
	}

	totalTableSize, err := m.Int64ObservableGauge("storage.pebble.table_size",
		metric.WithDescription("The total size in bytes of the sstables in the level. Note that if tables contain references to blob files, this quantity does not include the the size of the blob files or the referenced values."),
		metric.WithUnit("By"))
	if err != nil {
		return nil, err
	}

	return m.RegisterCallback(func(_ context.Context, o metric.Observer) error {
		backend.mu.RLock()
		pm := backend.db.Metrics()
		backend.mu.RUnlock()

		o.ObserveInt64(blockCacheSize, pm.BlockCache.Size)
		o.ObserveInt64(blockCacheCount, pm.BlockCache.Count)
		o.ObserveInt64(blockCacheHits, pm.BlockCache.Hits)
		o.ObserveInt64(blockCacheMisses, pm.BlockCache.Misses)
		o.ObserveInt64(compactionCount, pm.Compact.Count)
		o.ObserveInt64(ingestionCount, int64(pm.Ingest.Count))
		o.ObserveInt64(flushCount, pm.Flush.Count)
		o.ObserveInt64(filterHits, pm.Filter.Hits)
		o.ObserveInt64(filterMisses, pm.Filter.Misses)
		o.ObserveInt64(memTableSize, int64(pm.MemTable.Size))
		o.ObserveInt64(memTableCount, pm.MemTable.Count)
		o.ObserveInt64(snapshotCount, int64(pm.Snapshots.Count))
		o.ObserveInt64(walFiles, pm.WAL.Files)
		o.ObserveInt64(walSize, int64(pm.WAL.Size))
		o.ObserveInt64(diskSpaceUsage, int64(pm.DiskSpaceUsage()))
		o.ObserveInt64(virtualSSTables, int64(pm.NumVirtual()))
		o.ObserveInt64(virtualSize, int64(pm.VirtualSize()))
		o.ObserveInt64(readAmplification, int64(pm.ReadAmp()))
		total := pm.Total()
		o.ObserveInt64(totalSubLevels, int64(total.Sublevels))
		o.ObserveInt64(totalTableCount, total.TablesCount)
		o.ObserveInt64(totalTableSize, total.TablesSize)

		return nil
	},
		blockCacheSize,
		blockCacheCount,
		blockCacheHits,
		blockCacheMisses,
		compactionCount,
		ingestionCount,
		flushCount,
		filterHits,
		filterMisses,
		memTableSize,
		memTableCount,
		snapshotCount,
		walFiles,
		walSize,
		diskSpaceUsage,
		virtualSSTables,
		virtualSize,
		readAmplification,
		totalSubLevels,
		totalTableCount,
		totalTableSize,
	)
}
