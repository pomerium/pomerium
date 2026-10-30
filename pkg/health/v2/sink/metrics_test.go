package sink

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	healthv2 "github.com/pomerium/pomerium/pkg/health/v2"
	"github.com/pomerium/pomerium/pkg/health/v2/check"
)

type metricPoint struct {
	check, group, status, attr string
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
	return metricPoint{check: get("check"), group: get("group"), status: get("status"), attr: get("k")}
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
					got.startup[toPoint(dp.Attributes).check] = dp.Value
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

	snapshot := func(results ...check.Result) healthv2.Snapshot {
		return healthv2.Snapshot{Configured: true, Checkers: []healthv2.CheckerStatus{checkerStatus(check.GroupProxy, "c", results...)}}
	}
	group := string(check.GroupProxy)

	sink.Notify(snapshot(running("a"), failing("b", check.StatusUnknown, "boom")))
	sink.Notify(snapshot(running("a"), failing("b", check.StatusUnknown, "boom")))
	sink.Notify(snapshot(terminating("a"), failing("b", check.StatusUnknown, "boom")))

	got := collectMetrics(t, reader)
	assert.Equal(t, map[metricPoint]int64{
		{"a", group, "running", ""}:     1,
		{"a", group, "terminating", ""}: 1,
		{"b", group, "error", ""}:       1,
	}, got.counts, "unchanged results are not counted again")

	for _, st := range allStatusAttrs {
		want := int64(0)
		if st == "terminating" {
			want = 1
		}
		assert.Equal(t, want, got.gauge[metricPoint{"a", group, st, ""}], "a/%s", st)
		want = 0
		if st == "error" {
			want = 1
		}
		assert.Equal(t, want, got.gauge[metricPoint{"b", group, st, ""}], "b/%s", st)
	}

	assert.Contains(t, got.startup, "a")
	assert.NotContains(t, got.startup, "b", "unknown status has not started")
}

func TestMetricsSameNameInDifferentGroups(t *testing.T) {
	t.Parallel()

	reader := sdkmetric.NewManualReader()
	sink, err := NewMetrics(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)).Meter("test"), time.Now())
	require.NoError(t, err)

	snap := healthv2.Snapshot{Configured: true, Checkers: []healthv2.CheckerStatus{
		checkerStatus(check.GroupAuthorize, "c", running("a")),
		checkerStatus(check.GroupProxy, "c", failing("a", check.StatusRunning, "boom")),
	}}
	sink.Notify(snap)
	sink.Notify(snap)

	assert.Equal(t, map[metricPoint]int64{
		{"a", string(check.GroupAuthorize), "running", ""}: 1,
		{"a", string(check.GroupProxy), "error", ""}:       1,
	}, collectMetrics(t, reader).counts)
}

func TestMetricsResetsStaleSeries(t *testing.T) {
	t.Parallel()

	reader := sdkmetric.NewManualReader()
	sink, err := NewMetrics(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)).Meter("test"), time.Now())
	require.NoError(t, err)
	group := string(check.GroupProxy)
	snapshot := func(results ...check.Result) healthv2.Snapshot {
		return healthv2.Snapshot{Configured: true, Checkers: []healthv2.CheckerStatus{checkerStatus(check.GroupProxy, "c", results...)}}
	}

	sink.Notify(snapshot(running("a", check.Attr{Key: "k", Value: "v1"}), running("b")))
	sink.Notify(snapshot(running("a", check.Attr{Key: "k", Value: "v2"})))

	got := collectMetrics(t, reader).gauge
	assert.Equal(t, int64(0), got[metricPoint{"a", group, "running", "v1"}], "old attribute set")
	assert.Equal(t, int64(1), got[metricPoint{"a", group, "running", "v2"}], "new attribute set")
	assert.Equal(t, int64(0), got[metricPoint{"b", group, "running", ""}], "dropped check")
}
