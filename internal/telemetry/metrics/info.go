package metrics // import "github.com/pomerium/pomerium/internal/telemetry/metrics"

import (
	"context"
	"runtime"
	"sync"
	"time"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/version"

	"go.opencensus.io/metric"
	"go.opencensus.io/metric/metricdata"
	"go.opencensus.io/metric/metricproducer"
	"go.opencensus.io/stats"
	"go.opencensus.io/stats/view"
	"go.opencensus.io/tag"
)

var (
	// InfoViews contains opencensus views for informational metrics about
	// pomerium itself.
	InfoViews = []*view.View{ConfigLastReloadView, ConfigLastReloadSuccessView}

	configLastReload = stats.Int64(
		"config_last_reload_success_timestamp",
		"Timestamp of last successful config reload",
		"seconds")
	configLastReloadSuccess = stats.Int64(
		"config_last_reload_success",
		"Returns 1 if last reload was successful",
		"1")
	registry = newMetricRegistry()

	// ConfigLastReloadView contains the timestamp the configuration was last
	// reloaded, labeled by service.
	ConfigLastReloadView = &view.View{
		Name:        configLastReload.Name(),
		Description: configLastReload.Description(),
		Measure:     configLastReload,
		TagKeys:     []tag.Key{TagKeyService},
		Aggregation: view.LastValue(),
	}

	// ConfigLastReloadSuccessView contains the result of the last configuration
	// reload, labeled by service.
	ConfigLastReloadSuccessView = &view.View{
		Name:        configLastReloadSuccess.Name(),
		Description: configLastReloadSuccess.Description(),
		Measure:     configLastReloadSuccess,
		TagKeys:     []tag.Key{TagKeyService},
		Aggregation: view.LastValue(),
	}
)

// SetConfigInfo records the status, checksum and timestamp of a configuration
// reload. You must register InfoViews or the related config views before calling
func SetConfigInfo(service string, success bool) {

	if success {
		serviceTag := tag.Insert(TagKeyService, service)
		if err := stats.RecordWithTags(
			context.Background(),
			[]tag.Mutator{serviceTag},
			configLastReload.M(time.Now().Unix()),
		); err != nil {
			log.Error().Err(err).Msg("telemetry/metrics: failed to record config checksum timestamp")
		}

		if err := stats.RecordWithTags(
			context.Background(),
			[]tag.Mutator{serviceTag},
			configLastReloadSuccess.M(1),
		); err != nil {
			log.Error().Err(err).Msg("telemetry/metrics: failed to record config reload")
		}
	} else {
		stats.Record(context.Background(), configLastReloadSuccess.M(0))
	}
}

// metricRegistry holds the non-view metrics and handles safe
// initialization and updates.  Behavior without using newMetricRegistry()
// is undefined.
type metricRegistry struct {
	registry       *metric.Registry
	buildInfo      *metric.Int64Gauge
	policyCount    *metric.Int64DerivedGauge
	configChecksum *metric.Float64Gauge
	sync.Once
}

func newMetricRegistry() *metricRegistry {
	r := new(metricRegistry)
	r.init()
	return r
}

func (r *metricRegistry) init() {
	r.Do(
		func() {
			r.registry = metric.NewRegistry()
			var err error
			r.buildInfo, err = r.registry.AddInt64Gauge("build_info",
				metric.WithDescription("Build Metadata"),
				metric.WithLabelKeys("service", "version", "revision", "goversion"),
			)
			if err != nil {
				log.Error().Err(err).Msg("telemetry/metrics: failed to register build info metric")
			}

			r.configChecksum, err = r.registry.AddFloat64Gauge("config_checksum_decimal",
				metric.WithDescription("Config checksum represented in decimal notation"),
				metric.WithLabelKeys("service"),
			)
			if err != nil {
				log.Error().Err(err).Msg("telemetry/metrics: failed to register config checksum metric")
			}

			r.policyCount, err = r.registry.AddInt64DerivedGauge("policy_count_total",
				metric.WithDescription("Total number of policies loaded"),
				metric.WithLabelKeys("service"),
			)
			if err != nil {
				log.Error().Err(err).Msg("telemetry/metrics: failed to register policy count metric")
			}
		})
}

// SetBuildInfo records the pomerium build info. You must call RegisterInfoMetrics to
// have this exported
func (r *metricRegistry) setBuildInfo(service string) {
	if registry.buildInfo == nil {
		return
	}
	m, err := registry.buildInfo.GetEntry(
		metricdata.NewLabelValue(service),
		metricdata.NewLabelValue(version.FullVersion()),
		metricdata.NewLabelValue(version.GitCommit),
		metricdata.NewLabelValue((runtime.Version())),
	)
	if err != nil {
		log.Error().Err(err).Msg("telemetry/metrics: failed to get build info metric")
	}

	// This sets our build_info metric to a constant 1 per
	// https://www.robustperception.io/exposing-the-software-version-to-prometheus
	m.Set(1)
}

// SetBuildInfo records the pomerium build info. You must call RegisterInfoMetrics to
// have this exported
func SetBuildInfo(service string) {
	registry.setBuildInfo(service)
}

// RegisterInfoMetrics registers non-view based metrics registry globally for export
func RegisterInfoMetrics() {
	metricproducer.GlobalManager().AddProducer(registry.registry)
}

func (r *metricRegistry) setConfigChecksum(service string, checksum uint64) {
	if r.configChecksum == nil {
		return
	}
	m, err := r.configChecksum.GetEntry(metricdata.NewLabelValue(service))
	if err != nil {
		log.Error().Err(err).Msg("telemetry/metrics: failed to get config checksum metric")
	}
	m.Set(float64(checksum))
}

// SetConfigChecksum creates the configuration checksum metric.  You must call RegisterInfoMetrics to
// have this exported
func SetConfigChecksum(service string, checksum uint64) {
	registry.setConfigChecksum(service, checksum)
}

func (r *metricRegistry) addPolicyCountCallback(service string, f func() int64) {
	if r.policyCount == nil {
		return
	}
	err := r.policyCount.UpsertEntry(f, metricdata.NewLabelValue(service))
	if err != nil {
		log.Error().Err(err).Msg("telemetry/metrics: failed to get policy count metric")
	}
}

// AddPolicyCountCallback sets the function to call when exporting the
// policy count metric.   You must call RegisterInfoMetrics to have this
// exported
func AddPolicyCountCallback(service string, f func() int64) {
	registry.addPolicyCountCallback(service, f)
}
