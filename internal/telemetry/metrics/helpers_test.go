package metrics

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"go.opencensus.io/metric/metricdata"
)

func testMetricRetrieval(metrics []*metricdata.Metric, t *testing.T, labels []metricdata.LabelValue, value any, name string) {
	t.Helper()

	switch value.(type) {
	case int64:
	case float64:
	case uint64:
	default:
		t.Errorf("Got an unexpected type for value: %T", value)
	}

	found := false
	for _, metric := range metrics {
		if metric.Descriptor.Name != name {
			found = true
			continue
		}
		gotLabels := metric.TimeSeries[0].LabelValues
		gotValue := metric.TimeSeries[0].Points[0].Value

		if diff := cmp.Diff(gotLabels, labels); diff != "" {
			t.Errorf("Failed to find metric labels:\n%s", diff)
		}
		if diff := cmp.Diff(gotValue, value); diff != "" {
			t.Errorf("Failed to find metric value:\n%s", diff)
		}
	}
	if !found {
		t.Errorf("Could not find metric %s", name)
	}
}
