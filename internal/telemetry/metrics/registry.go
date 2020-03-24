package metrics

import (
	"runtime"
	"sync"

	"go.opencensus.io/metric"
	"go.opencensus.io/metric/metricdata"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/version"
)

var (
	registry = newMetricRegistry()
)

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

func (r *metricRegistry) addPolicyCountCallback(service string, f func() int64) {
	if r.policyCount == nil {
		return
	}
	err := r.policyCount.UpsertEntry(f, metricdata.NewLabelValue(service))
	if err != nil {
		log.Error().Err(err).Msg("telemetry/metrics: failed to get policy count metric")
	}
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

func (r *metricRegistry) addInt64DerivedGaugeMetric(name string, desc string, service string, f func() int64) {

	m, err := r.registry.AddInt64DerivedGauge(name, metric.WithDescription(desc), metric.WithLabelKeys("service"))
	if err != nil {
		log.Error().Err(err).Str("service", service).Msg("telemetry/metrics: failed to register metric")
		return
	}

	err = m.UpsertEntry(
		f,
		metricdata.NewLabelValue(service),
	)
	if err != nil {
		log.Error().Err(err).Str("service", service).Msg("telemetry/metrics: failed to update metric")
		return
	}
}

func (r *metricRegistry) addInt64DerivedCumulativeMetric(name string, desc string, service string, f func() int64) {

	m, err := r.registry.AddInt64DerivedCumulative(name, metric.WithDescription(desc), metric.WithLabelKeys("service"))
	if err != nil {
		log.Error().Err(err).Str("service", service).Msg("telemetry/metrics: failed to register metric")
		return
	}

	err = m.UpsertEntry(
		f,
		metricdata.NewLabelValue(service),
	)
	if err != nil {
		log.Error().Err(err).Str("service", service).Msg("telemetry/metrics: failed to update metric")
		return
	}
}
