package metrics

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"go.opencensus.io/metric/metricdata"

	"github.com/pomerium/pomerium/pkg/metrics"
)

func TestPgxpoolStatMetrics(t *testing.T) {
	registry = newMetricRegistry()
	registerPgxpoolStatMetrics(registry.registry)

	config, err := pgxpool.ParseConfig("pool_max_conns=42")
	require.NoError(t, err)
	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	require.NoError(t, err)

	ConnectPgxpoolStatMetrics(pool)

	testMetricRetrieval(registry.registry.Read(), t, []metricdata.LabelValue{},
		int64(0), metrics.PgxpoolAcquireCount)
	testMetricRetrieval(registry.registry.Read(), t, []metricdata.LabelValue{},
		float64(0), metrics.PgxpoolAcquireDurationSeconds)
	testMetricRetrieval(registry.registry.Read(), t, []metricdata.LabelValue{},
		int64(0), metrics.PgxpoolAcquiredConns)
	testMetricRetrieval(registry.registry.Read(), t, []metricdata.LabelValue{},
		int64(0), metrics.PgxpoolCanceledAcquireCount)
	testMetricRetrieval(registry.registry.Read(), t, []metricdata.LabelValue{},
		int64(0), metrics.PgxpoolConstructingConns)
	testMetricRetrieval(registry.registry.Read(), t, []metricdata.LabelValue{},
		int64(0), metrics.PgxpoolEmptyAcquireCount)
	testMetricRetrieval(registry.registry.Read(), t, []metricdata.LabelValue{},
		int64(0), metrics.PgxpoolIdleConns)
	testMetricRetrieval(registry.registry.Read(), t, []metricdata.LabelValue{},
		int64(42), metrics.PgxpoolMaxConns)
	testMetricRetrieval(registry.registry.Read(), t, []metricdata.LabelValue{},
		int64(0), metrics.PgxpoolMaxIdleDestroyCount)
	testMetricRetrieval(registry.registry.Read(), t, []metricdata.LabelValue{},
		int64(0), metrics.PgxpoolMaxLifetimeDestroyCount)
	testMetricRetrieval(registry.registry.Read(), t, []metricdata.LabelValue{},
		int64(0), metrics.PgxpoolNewConnsCount)
}
