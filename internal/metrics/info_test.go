package metrics // import "github.com/pomerium/pomerium/internal/metrics"

import (
	"runtime"
	"testing"

	"github.com/pomerium/pomerium/internal/version"

	"go.opencensus.io/metric/metricdata"
	"go.opencensus.io/metric/metricproducer"
)

func Test_SetConfigInfo(t *testing.T) {
	tests := []struct {
		name                  string
		success               bool
		checksum              string
		wantLastReload        string
		wantLastReloadSuccess string
	}{
		{"success", true, "abcde", "{ { {service test_service} }&{1.", "{ { {service test_service} }&{1} }"},
		{"failed", false, "abcde", "", "{ {  }&{0} }"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			UnRegisterView(InfoViews)
			RegisterView(InfoViews)

			SetConfigInfo("test_service", tt.success, tt.checksum)

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
	testMetricRetrieval(registry.registry.Read(), t, wantLabels, 1, "build_info")
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

	wantValue := int64(42)
	wantLabels := []metricdata.LabelValue{{Value: "test_service", Present: true}}
	SetConfigChecksum("test_service", wantValue)

	testMetricRetrieval(registry.registry.Read(), t, wantLabels, wantValue, "config_checksum_int64")
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
