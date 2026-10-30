package sink

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	healthv2 "github.com/pomerium/pomerium/pkg/health/v2"
)

type metricPoint struct {
	group, checker, status string
}

type collectedMetrics struct {
	counts  map[metricPoint]int64
	gauge   map[metricPoint]int64
	startup map[string]float64
}

func toPoint(set attribute.Set) metricPoint {
	get := func(key attribute.Key) string {
		v, _ := set.Value(key)
		return v.AsString()
	}
	return metricPoint{group: get("group"), checker: get("checker"), status: get("status")}
}

func collectMetrics(t *testing.T, reader *sdkmetric.ManualReader) collectedMetrics {
	t.Helper()
	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(t.Context(), &rm))

	got := collectedMetrics{counts: map[metricPoint]int64{}, gauge: map[metricPoint]int64{}, startup: map[string]float64{}}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			switch data := m.Data.(type) {
			case metricdata.Sum[int64]:
				for _, dp := range data.DataPoints {
					got.counts[toPoint(dp.Attributes)] += dp.Value
				}
			case metricdata.Gauge[int64]:
				for _, dp := range data.DataPoints {
					got.gauge[toPoint(dp.Attributes)] = dp.Value
				}
			case metricdata.Gauge[float64]:
				for _, dp := range data.DataPoints {
					got.startup[toPoint(dp.Attributes).checker] = dp.Value
				}
			}
		}
	}
	return got
}

func TestMetrics(t *testing.T) {
	t.Parallel()

	reader := sdkmetric.NewManualReader()
	sink, err := NewMetrics(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)).Meter("test"), time.Now())
	require.NoError(t, err)
	group := string(healthv2.ServiceProxy)

	sink.Notify(snapshotOf(running("a"), uninitialized(checkerStatus("b", pass(nil), fail("boom")), "loading"), uninitialized(running("c"), "loading")))
	sink.Notify(snapshotOf(running("a"), uninitialized(checkerStatus("b", pass(nil), fail("boom")), "loading"), uninitialized(running("c"), "loading")))
	sink.Notify(snapshotOf(
		checkerStatus("a", pass(map[string]string{"k": "v"}), pass(nil)),
		uninitialized(checkerStatus("b", pass(nil), fail("other")), "loading"),
		checkerStatus("c", fail("syncing"), pass(nil)),
	))

	got := collectMetrics(t, reader)
	assert.Equal(t, map[metricPoint]int64{
		{group, "a", "ok"}:        1,
		{group, "b", "unhealthy"}: 1,
		{group, "c", "starting"}:  1,
		{group, "c", "not_ready"}: 1,
	}, got.counts, "unchanged states are not counted again")
	assertGauge(t, got, map[string]string{"a": "ok", "b": "unhealthy", "c": "not_ready"})

	assert.Contains(t, got.startup, "a")
	assert.NotContains(t, got.startup, "b", "never initialized")
	assert.Contains(t, got.startup, "c", "initialized but not ready")
}

func TestMetricsShutdown(t *testing.T) {
	t.Parallel()

	reader := sdkmetric.NewManualReader()
	sink, err := NewMetrics(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)).Meter("test"), time.Now())
	require.NoError(t, err)
	group := string(healthv2.ServiceProxy)
	shutdownCtx, cancel := context.WithCancel(t.Context())
	cancel()

	sink.Notify(snapshotOf(running("a"), checkerStatus("b", pass(nil), fail("boom"))))
	wantCounts := map[metricPoint]int64{
		{group, "a", "ok"}:          1,
		{group, "a", "terminating"}: 1,
		{group, "b", "unhealthy"}:   1,
	}

	t.Run("shutdown", func(t *testing.T) {
		sink.Shutdown(shutdownCtx)
		got := collectMetrics(t, reader)
		assert.Equal(t, wantCounts, got.counts)
		assertGauge(t, got, map[string]string{"a": "terminating", "b": "unhealthy"})
	})
	t.Run("shutdown_once", func(t *testing.T) {
		sink.Shutdown(shutdownCtx)
		assert.Equal(t, wantCounts, collectMetrics(t, reader).counts)
	})
}

func assertGauge(t *testing.T, got collectedMetrics, want map[string]string) {
	t.Helper()
	for checker, current := range want {
		for _, status := range allStatuses {
			var v int64
			if status == current {
				v = 1
			}
			assert.Equal(t, v, got.gauge[metricPoint{string(healthv2.ServiceProxy), checker, status}], "%s/%s", checker, status)
		}
	}
}

func TestMetricsSameNameInDifferentGroups(t *testing.T) {
	t.Parallel()

	reader := sdkmetric.NewManualReader()
	sink, err := NewMetrics(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)).Meter("test"), time.Now())
	require.NoError(t, err)

	snap := snapshotOf(
		healthv2.CheckerStatus{Service: healthv2.ServiceAuthorize, Name: "c", Initialized: pass(nil), Ready: pass(nil), Healthy: pass(nil)},
		healthv2.CheckerStatus{Service: healthv2.ServiceProxy, Name: "c", Initialized: pass(nil), Ready: pass(nil), Healthy: fail("boom")},
	)
	sink.Notify(snap)
	sink.Notify(snap)

	assert.Equal(t, map[metricPoint]int64{
		{string(healthv2.ServiceAuthorize), "c", "ok"}:    1,
		{string(healthv2.ServiceProxy), "c", "unhealthy"}: 1,
	}, collectMetrics(t, reader).counts)
}
