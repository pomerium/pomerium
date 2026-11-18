package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/attribute"
	sdk_metric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	semconv "go.opentelemetry.io/otel/semconv/v1.40.0"
)

func TestHTTPServerAddressView(t *testing.T) {
	reader := sdk_metric.NewManualReader()
	mp := sdk_metric.NewMeterProvider(
		sdk_metric.WithReader(reader),
		sdk_metric.WithView(httpServerAddressView),
	)
	h := otelhttp.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), "test", otelhttp.WithMeterProvider(mp))
	for _, host := range []string{"a.example.com", "b.example.com", "c.example.com:8443"} {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "http://"+host+"/", nil))
	}

	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(t.Context(), &rm))

	var names []string
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if !strings.HasPrefix(m.Name, "http.server.") {
				continue
			}
			names = append(names, m.Name)
			sets := histogramAttributeSets(t, m.Data)
			require.Len(t, sets, 1, m.Name)
			for _, key := range []attribute.Key{semconv.ServerAddressKey, semconv.ServerPortKey} {
				_, ok := sets[0].Value(key)
				assert.False(t, ok, "%s has %s", m.Name, key)
			}
		}
	}
	assert.ElementsMatch(t, []string{
		"http.server.request.duration",
		"http.server.request.body.size",
		"http.server.response.body.size",
	}, names)
}

func histogramAttributeSets(t *testing.T, data metricdata.Aggregation) []attribute.Set {
	t.Helper()
	var sets []attribute.Set
	switch d := data.(type) {
	case metricdata.Histogram[int64]:
		for _, dp := range d.DataPoints {
			sets = append(sets, dp.Attributes)
		}
	case metricdata.Histogram[float64]:
		for _, dp := range d.DataPoints {
			sets = append(sets, dp.Attributes)
		}
	default:
		t.Fatalf("unexpected aggregation %T", data)
	}
	return sets
}
