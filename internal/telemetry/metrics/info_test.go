package metrics

import (
	"context"
	"fmt"
	"runtime"
	"testing"

	"go.opencensus.io/metric/metricdata"
	"go.opencensus.io/metric/metricproducer"
	"go.opencensus.io/stats/view"

	"github.com/pomerium/pomerium/internal/version"
	"github.com/pomerium/pomerium/pkg/metrics"
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
			SetConfigInfo(context.Background(), "test_service", "test config", 0, tt.success)

			testDataRetrieval(ConfigLastReloadView, t, tt.wantLastReload)
			testDataRetrieval(ConfigLastReloadSuccessView, t, tt.wantLastReloadSuccess)
		})
	}
}

func Test_SetDBConfigInfo(t *testing.T) {
	tests := []struct {
		version     uint64
		errCount    int64
		wantVersion string
		wantErrors  string
	}{
		{
			1,
			2,
			"{ { {config_id test_config}{service test_service} }&{1} }",
			"{ { {config_id test_config}{service test_service} }&{2} }",
		},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("version=%d errors=%d", tt.version, tt.errCount), func(t *testing.T) {
			view.Unregister(InfoViews...)
			view.Register(InfoViews...)
			SetDBConfigInfo(context.TODO(), "test_service", "test_config", tt.version, tt.errCount)

			testDataRetrieval(ConfigDBVersionView, t, tt.wantVersion)
			testDataRetrieval(ConfigDBErrorsView, t, tt.wantErrors)
		})
	}
}

func Test_SetBuildInfo(t *testing.T) {
	initTemporaryMetricsRegistry(t)

	version.Version = "v0.0.1"
	version.GitCommit = "deadbeef"

	wantLabels := []metricdata.LabelValue{
		{Value: "test_service", Present: true},
		{Value: version.FullVersion(), Present: true},
		{Value: "v1.2.3", Present: true},
		{Value: version.GitCommit, Present: true},
		{Value: runtime.Version(), Present: true},
		{Value: "test_host", Present: true},
	}

	SetBuildInfo("test_service", "test_host", "v1.2.3")
	testMetricRetrieval(registry.registry.Read(), t, wantLabels, int64(1), metrics.BuildInfo)
}

func Test_AddPolicyCountCallback(t *testing.T) {
	initTemporaryMetricsRegistry(t)

	wantValue := int64(42)
	wantLabels := []metricdata.LabelValue{
		{Value: "test_service", Present: true},
	}
	AddPolicyCountCallback("test_service", func() int64 { return wantValue })

	testMetricRetrieval(registry.registry.Read(), t, wantLabels, wantValue, metrics.PolicyCountTotal)
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

func initTemporaryMetricsRegistry(t *testing.T) {
	original := registry
	registry = newMetricRegistry()
	t.Cleanup(func() { registry = original })
}
