package metrics

import (
	"context"
	"runtime"
	"sync"

	"go.opencensus.io/metric"
	"go.opencensus.io/metric/metricdata"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/version"
	"github.com/pomerium/pomerium/pkg/metrics"
)

var registry = newMetricRegistry()

// metricRegistry holds the non-view metrics and handles safe
// initialization and updates.  Behavior without using newMetricRegistry()
// is undefined.
//
// It is not safe to use metricRegistry concurrently.
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
	ctx := context.TODO()
	r.Do(
		func() {
			r.registry = metric.NewRegistry()
			var err error
			r.buildInfo, err = r.registry.AddInt64Gauge(metrics.BuildInfo,
				metric.WithDescription("Build Metadata"),
				metric.WithLabelKeys(
					metrics.ServiceLabel,
					metrics.VersionLabel,
					metrics.EnvoyVersionLabel,
					metrics.RevisionLabel,
					metrics.GoVersionLabel,
					metrics.HostLabel,
				),
			)
			if err != nil {
				log.Ctx(ctx).Error().Err(err).Msg("telemetry/metrics: failed to register build info metric")
			}

			r.configChecksum, err = r.registry.AddFloat64Gauge(metrics.ConfigChecksumDecimal,
				metric.WithDescription("Config checksum represented in decimal notation"),
				metric.WithLabelKeys(metrics.ServiceLabel, metrics.ConfigLabel),
			)
			if err != nil {
				log.Ctx(ctx).Error().Err(err).Msg("telemetry/metrics: failed to register config checksum metric")
			}

			r.policyCount, err = r.registry.AddInt64DerivedGauge(metrics.PolicyCountTotal,
				metric.WithDescription("Total number of policies loaded"),
				metric.WithLabelKeys(metrics.ServiceLabel),
			)
			if err != nil {
				log.Ctx(ctx).Error().Err(err).Msg("telemetry/metrics: failed to register policy count metric")
			}

			err = registerAutocertMetrics(r.registry)
			if err != nil {
				log.Ctx(ctx).Error().Err(err).Msg("telemetry/metrics: failed to register autocert metrics")
			}
		})
}

// SetBuildInfo records the pomerium build info. You must call RegisterInfoMetrics to
// have this exported
func (r *metricRegistry) setBuildInfo(service, hostname, envoyVersion string) {
	if registry.buildInfo == nil {
		return
	}
	m, err := registry.buildInfo.GetEntry(
		metricdata.NewLabelValue(service),
		metricdata.NewLabelValue(version.FullVersion()),
		metricdata.NewLabelValue(envoyVersion),
		metricdata.NewLabelValue(version.GitCommit),
		metricdata.NewLabelValue((runtime.Version())),
		metricdata.NewLabelValue(hostname),
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

func (r *metricRegistry) setConfigChecksum(service string, configName string, checksum uint64) {
	if r.configChecksum == nil {
		return
	}
	m, err := r.configChecksum.GetEntry(metricdata.NewLabelValue(service), metricdata.NewLabelValue(configName))
	if err != nil {
		log.Error().Err(err).Msg("telemetry/metrics: failed to get config checksum metric")
	}
	m.Set(float64(checksum))
}
