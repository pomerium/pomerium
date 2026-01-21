package health_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	health "github.com/pomerium/pomerium/pkg/health"
)

type metricsTestSetup struct {
	ctx     context.Context
	mgr     health.ProviderManager
	mp      *health.MetricsProvider
	reader  *sdkmetric.ManualReader
	metrics *health.Metrics
}

func setupMetricsTest(t *testing.T, startTime time.Time) *metricsTestSetup {
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	meter := provider.Meter("test")

	metrics, err := health.NewMetrics(meter)
	require.NoError(t, err)

	ctx := context.Background()
	mgr := health.NewManager()

	mp := health.NewMetricsProvider(ctx, metrics, mgr, startTime)
	mgr.Register(health.ProviderID("metrics"), mp)

	return &metricsTestSetup{
		ctx:     ctx,
		mgr:     mgr,
		mp:      mp,
		reader:  reader,
		metrics: metrics,
	}
}

func TestMetricsProvider_Counter(t *testing.T) {
	t.Parallel()

	setup := setupMetricsTest(t, time.Now())
	a, b, c := health.Check("a"), health.Check("b"), health.Check("c")

	setup.mgr.ReportStatus(a, health.StatusRunning, health.StrAttr("foo", "bar"))
	setup.mgr.ReportStatus(c, health.StatusRunning, health.StrAttr("foo", "baz"))
	setup.mgr.ReportStatus(b, health.StatusTerminating, health.StrAttr("foo", "bar"))
	setup.mgr.ReportError(b, fmt.Errorf("some error"), health.StrAttr("foo", "bar"))

	var rm metricdata.ResourceMetrics
	err := setup.reader.Collect(setup.ctx, &rm)
	require.NoError(t, err)

	require.Len(t, rm.ScopeMetrics, 1)
	scopeMetrics := rm.ScopeMetrics[0]

	var totalCount int64
	var runningCount int64
	var terminatingCount int64
	var errorCount int64
	countPerCheck := map[string]int64{}
	for _, m := range scopeMetrics.Metrics {
		if m.Name != "health.status.total" {
			continue
		}

		sum, ok := m.Data.(metricdata.Sum[int64])
		require.True(t, ok)
		for _, dp := range sum.DataPoints {
			ch, ok := dp.Attributes.Value("check")
			require.True(t, ok, "did not include check label")
			countPerCheck[ch.AsString()]++
			st, ok := dp.Attributes.Value("status")
			require.True(t, ok, "did not included status label")
			switch st.AsString() {
			case "running":
				runningCount++
			case "terminating":
				terminatingCount++
			case "error":
				errorCount++
			}
			totalCount += dp.Value
		}
	}

	assert.Equal(t, int64(4), totalCount)
	assert.Equal(t, int64(2), runningCount)
	assert.Equal(t, int64(1), terminatingCount)
	assert.Equal(t, map[string]int64{
		"a": 1,
		"b": 2,
		"c": 1,
	}, countPerCheck)
}

func TestMetricsProvider_StartupGauge(t *testing.T) {
	t.Parallel()

	startTime := time.Now().Add(-5 * time.Second)
	setup := setupMetricsTest(t, startTime)
	check := health.Check("a")

	setup.mgr.ReportStatus(check, health.StatusRunning)

	var rm metricdata.ResourceMetrics
	err := setup.reader.Collect(setup.ctx, &rm)
	require.NoError(t, err)

	require.Len(t, rm.ScopeMetrics, 1)
	scopeMetrics := rm.ScopeMetrics[0]

	foundStartupMetric := false
	for _, m := range scopeMetrics.Metrics {
		if m.Name == "health.startup.duration" {
			foundStartupMetric = true
			gauge, ok := m.Data.(metricdata.Gauge[float64])
			require.True(t, ok)
			require.Greater(t, len(gauge.DataPoints), 0)
			// verify the duration is approximately 5 seconds
			assert.Greater(t, gauge.DataPoints[0].Value, 4.0)
			assert.Less(t, gauge.DataPoints[0].Value, 6.0)
		}
	}

	assert.True(t, foundStartupMetric)
}

func TestMetricsProvider_StatusGauge(t *testing.T) {
	t.Parallel()
	setup := setupMetricsTest(t, time.Now())
	check := health.Check("a")

	// Helper to collect gauge values for a specific check
	collectGaugeValues := func() map[string]int64 {
		var rm metricdata.ResourceMetrics
		err := setup.reader.Collect(setup.ctx, &rm)
		require.NoError(t, err)

		require.Len(t, rm.ScopeMetrics, 1)
		scopeMetrics := rm.ScopeMetrics[0]

		values := make(map[string]int64)
		for _, m := range scopeMetrics.Metrics {
			if m.Name != "health.status" {
				continue
			}

			gauge, ok := m.Data.(metricdata.Gauge[int64])
			require.True(t, ok)
			for _, dp := range gauge.DataPoints {
				ch, ok := dp.Attributes.Value("check")
				require.True(t, ok)
				if ch.AsString() != string(check) {
					continue
				}
				status, ok := dp.Attributes.Value("status")
				require.True(t, ok)
				values[status.AsString()] = dp.Value
			}
		}
		return values
	}

	setup.mgr.ReportStatus(check, health.StatusRunning)
	values := collectGaugeValues()
	assert.Equal(t, int64(1), values["running"], "running should be 1")
	assert.Equal(t, int64(0), values["terminating"], "terminating should be 0")
	assert.Equal(t, int64(0), values["error"], "error should be 0")

	setup.mgr.ReportError(check, fmt.Errorf("test error"))
	values = collectGaugeValues()
	assert.Equal(t, int64(0), values["running"], "running should be 0")
	assert.Equal(t, int64(0), values["terminating"], "terminating should be 0")
	assert.Equal(t, int64(1), values["error"], "error should be 1")

	setup.mgr.ReportStatus(check, health.StatusTerminating)
	values = collectGaugeValues()
	assert.Equal(t, int64(0), values["running"], "running should be 0")
	assert.Equal(t, int64(1), values["terminating"], "terminating should be 1")
	assert.Equal(t, int64(0), values["error"], "error should be 0")
}
