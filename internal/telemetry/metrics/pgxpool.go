package metrics

import (
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.opencensus.io/metric"

	"github.com/pomerium/pomerium/pkg/metrics"
)

var (
	pgxpoolAcquireCount            *metric.Int64DerivedGauge
	pgxpoolAcquireDurationSeconds  *metric.Float64DerivedGauge
	pgxpoolAcquiredConns           *metric.Int64DerivedGauge
	pgxpoolCanceledAcquireCount    *metric.Int64DerivedGauge
	pgxpoolConstructingConns       *metric.Int64DerivedGauge
	pgxpoolEmptyAcquireCount       *metric.Int64DerivedGauge
	pgxpoolIdleConns               *metric.Int64DerivedGauge
	pgxpoolMaxConns                *metric.Int64DerivedGauge
	pgxpoolMaxIdleDestroyCount     *metric.Int64DerivedGauge
	pgxpoolMaxLifetimeDestroyCount *metric.Int64DerivedGauge
	pgxpoolNewConnsCount           *metric.Int64DerivedGauge
)

func registerPgxpoolStatMetrics(registry *metric.Registry) {
	pgxpoolAcquireCount, _ = registry.AddInt64DerivedGauge(
		metrics.PgxpoolAcquireCount,
		metric.WithDescription("Cumulative count of successful acquires from the current database connection pool."),
	)
	pgxpoolAcquireDurationSeconds, _ = registry.AddFloat64DerivedGauge(
		metrics.PgxpoolAcquireDurationSeconds,
		metric.WithDescription("Total duration of all successful acquires from the current database connection pool."),
	)
	pgxpoolAcquiredConns, _ = registry.AddInt64DerivedGauge(
		metrics.PgxpoolAcquiredConns,
		metric.WithDescription("Number of currently acquired connections in the current database connection pool."),
	)
	pgxpoolCanceledAcquireCount, _ = registry.AddInt64DerivedGauge(
		metrics.PgxpoolCanceledAcquireCount,
		metric.WithDescription("Cumulative count of acquires from the current database connection pool that were canceled by a context."),
	)
	pgxpoolConstructingConns, _ = registry.AddInt64DerivedGauge(
		metrics.PgxpoolConstructingConns,
		metric.WithDescription("Number of connections with construction in progress in the current database connection pool."),
	)
	pgxpoolEmptyAcquireCount, _ = registry.AddInt64DerivedGauge(
		metrics.PgxpoolEmptyAcquireCount,
		metric.WithDescription("Cumulative count of successful acquires from the current database connection pool that waited for a resource to be released or constructed because the pool was empty."),
	)
	pgxpoolIdleConns, _ = registry.AddInt64DerivedGauge(
		metrics.PgxpoolIdleConns,
		metric.WithDescription("Number of currently idle connections in the current database connection pool."),
	)
	pgxpoolMaxConns, _ = registry.AddInt64DerivedGauge(
		metrics.PgxpoolMaxConns,
		metric.WithDescription("Maximum size of the current database connection pool."),
	)
	pgxpoolMaxIdleDestroyCount, _ = registry.AddInt64DerivedGauge(
		metrics.PgxpoolMaxIdleDestroyCount,
		metric.WithDescription("Cumulative count of database connections destroyed by the current database connection pool because they exceeded the MaxConnIdleTime."),
	)
	pgxpoolMaxLifetimeDestroyCount, _ = registry.AddInt64DerivedGauge(
		metrics.PgxpoolMaxLifetimeDestroyCount,
		metric.WithDescription("Cumulative count of database connections destroyed by the current database connection pool because they exceeded the MaxConnLifetime."),
	)
	pgxpoolNewConnsCount, _ = registry.AddInt64DerivedGauge(
		metrics.PgxpoolNewConnsCount,
		metric.WithDescription("Cumulative count of new database connections opened by the current database connection pool."),
	)
}

func ConnectPgxpoolStatMetrics(pool *pgxpool.Pool) {
	var w = pgxpoolStatsWrapper{pool: pool}
	w.connect()
}

type pgxpoolStatsWrapper struct {
	pool      *pgxpool.Pool
	mu        sync.Mutex
	cached    *pgxpool.Stat
	timestamp time.Time
}

func (w *pgxpoolStatsWrapper) stats() *pgxpool.Stat {
	// Don't request a new stats snapshot more often than this interval.
	const cacheInterval = 5 * time.Second

	w.mu.Lock()
	defer w.mu.Unlock()

	if w.cached == nil || time.Since(w.timestamp) > cacheInterval {
		w.cached = w.pool.Stat()
	}

	return w.cached
}

func (w *pgxpoolStatsWrapper) acquireCount() int64 {
	return w.stats().AcquireCount()
}

func (w *pgxpoolStatsWrapper) acquireDurationSeconds() float64 {
	return w.stats().AcquireDuration().Seconds()
}

func (w *pgxpoolStatsWrapper) acquiredConns() int64 {
	return int64(w.stats().AcquiredConns())
}

func (w *pgxpoolStatsWrapper) canceledAcquireCount() int64 {
	return w.stats().CanceledAcquireCount()
}

func (w *pgxpoolStatsWrapper) constructingConns() int64 {
	return int64(w.stats().ConstructingConns())
}

func (w *pgxpoolStatsWrapper) emptyAcquireCount() int64 {
	return w.stats().EmptyAcquireCount()
}

func (w *pgxpoolStatsWrapper) idleConns() int64 {
	return int64(w.stats().IdleConns())
}

func (w *pgxpoolStatsWrapper) maxConns() int64 {
	return int64(w.stats().MaxConns())
}

func (w *pgxpoolStatsWrapper) maxIdleDestroyCount() int64 {
	return w.stats().MaxIdleDestroyCount()
}

func (w *pgxpoolStatsWrapper) maxLifetimeDestroyCount() int64 {
	return w.stats().MaxLifetimeDestroyCount()
}

func (w *pgxpoolStatsWrapper) newConnsCount() int64 {
	return w.stats().NewConnsCount()
}

func (w *pgxpoolStatsWrapper) connect() {
	pgxpoolAcquireCount.UpsertEntry(w.acquireCount)
	pgxpoolAcquireDurationSeconds.UpsertEntry(w.acquireDurationSeconds)
	pgxpoolAcquiredConns.UpsertEntry(w.acquiredConns)
	pgxpoolCanceledAcquireCount.UpsertEntry(w.canceledAcquireCount)
	pgxpoolConstructingConns.UpsertEntry(w.constructingConns)
	pgxpoolEmptyAcquireCount.UpsertEntry(w.emptyAcquireCount)
	pgxpoolIdleConns.UpsertEntry(w.idleConns)
	pgxpoolMaxConns.UpsertEntry(w.maxConns)
	pgxpoolMaxIdleDestroyCount.UpsertEntry(w.maxIdleDestroyCount)
	pgxpoolMaxLifetimeDestroyCount.UpsertEntry(w.maxLifetimeDestroyCount)
	pgxpoolNewConnsCount.UpsertEntry(w.newConnsCount)
}
