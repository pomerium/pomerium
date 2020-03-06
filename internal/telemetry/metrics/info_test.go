package metrics // import "github.com/pomerium/pomerium/internal/telemetry/metrics"

import (
	"runtime"
	"testing"

	"github.com/pomerium/pomerium/internal/version"

	"go.opencensus.io/metric/metricdata"
	"go.opencensus.io/metric/metricproducer"
	"go.opencensus.io/stats/view"
)

func Test_SetConfigInfo(t *testing.T) {
	tests := []struct {
		name                  string
		success               bool
		wantLastReload        string
		wantLastReloadSuccess string
	}{
		{"success", true, "{ { {service test_service} }&{1.", "{ { {service test_service} }&{1} }"},
		{"failed", false, "", "{ {  }&{0} }"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			view.Unregister(InfoViews...)
			view.Register(InfoViews...)
			SetConfigInfo("test_service", tt.success)

			testDataRetrieval(ConfigLastReloadView, t, tt.wantLastReload)
			testDataRetrieval(ConfigLastReloadSuccessView, t, tt.wantLastReloadSuccess)
		})
	}
}

func Test_SetBuildInfo(t *testing.T) {
	registry = newMetricRegistry()

	version.Version = "v0.0.1"
	version.GitCommit = "deadbeef"

	wantLabels := []metricdata.LabelValue{
		{Value: "test_service", Present: true},
		{Value: version.FullVersion(), Present: true},
		{Value: version.GitCommit, Present: true},
		{Value: runtime.Version(), Present: true},
	}

	SetBuildInfo("test_service")
	testMetricRetrieval(registry.registry.Read(), t, wantLabels, int64(1), "build_info")
}

func Test_AddPolicyCountCallback(t *testing.T) {
	registry = newMetricRegistry()

	wantValue := int64(42)
	wantLabels := []metricdata.LabelValue{{Value: "test_service", Present: true}}
	AddPolicyCountCallback("test_service", func() int64 { return wantValue })

	testMetricRetrieval(registry.registry.Read(), t, wantLabels, wantValue, "policy_count_total")
}

func Test_SetConfigChecksum(t *testing.T) {
	registry = newMetricRegistry()

	wantValue := uint64(42)
	wantLabels := []metricdata.LabelValue{{Value: "test_service", Present: true}}
	SetConfigChecksum("test_service", wantValue)

	testMetricRetrieval(registry.registry.Read(), t, wantLabels, float64(wantValue), "config_checksum_decimal")
}

func Test_RegisterInfoMetrics(t *testing.T) {
	metricproducer.GlobalManager().DeleteProducer(registry.registry)
	RegisterInfoMetrics()
	// Make sure registration de-dupes on multiple calls
	RegisterInfoMetrics()

	r := metricproducer.GlobalManager().GetAll()
	if len(r) != 2 {
		t.Error("Did not find enough registries")
	}
}
