package metrics

import (
	"context"
	"fmt"
	"runtime"
	"sync"

	"go.opencensus.io/metric"
	"go.opencensus.io/metric/metricdata"

	"github.com/pomerium/pomerium/internal/envoy/files"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/version"
	"github.com/pomerium/pomerium/pkg/metrics"
)

var registry = newMetricRegistry(context.Background())

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

func newMetricRegistry(ctx context.Context) *metricRegistry {
	r := new(metricRegistry)
	r.init(ctx)
	return r
}

func (r *metricRegistry) init(ctx context.Context) {
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
				log.Error(ctx).Err(err).Msg("telemetry/metrics: failed to register build info metric")
			}

			r.configChecksum, err = r.registry.AddFloat64Gauge(metrics.ConfigChecksumDecimal,
				metric.WithDescription("Config checksum represented in decimal notation"),
				metric.WithLabelKeys(metrics.ServiceLabel, metrics.ConfigLabel),
			)
			if err != nil {
				log.Error(ctx).Err(err).Msg("telemetry/metrics: failed to register config checksum metric")
			}

			r.policyCount, err = r.registry.AddInt64DerivedGauge(metrics.PolicyCountTotal,
				metric.WithDescription("Total number of policies loaded"),
				metric.WithLabelKeys(metrics.ServiceLabel),
			)
			if err != nil {
				log.Error(ctx).Err(err).Msg("telemetry/metrics: failed to register policy count metric")
			}

			err = registerAutocertMetrics(r.registry)
			if err != nil {
				log.Error(ctx).Err(err).Msg("telemetry/metrics: failed to register autocert metrics")
			}
		})
}

// SetBuildInfo records the pomerium build info. You must call RegisterInfoMetrics to
// have this exported
func (r *metricRegistry) setBuildInfo(service, hostname string) error {
	if registry.buildInfo == nil {
		return nil
	}
	m, err := registry.buildInfo.GetEntry(
		metricdata.NewLabelValue(service),
		metricdata.NewLabelValue(version.FullVersion()),
		metricdata.NewLabelValue(files.FullVersion()),
		metricdata.NewLabelValue(version.GitCommit),
		metricdata.NewLabelValue((runtime.Version())),
		metricdata.NewLabelValue(hostname),
	)
	if err != nil {
		return fmt.Errorf("failed to get build info metric: %w", err)
	}

	// This sets our build_info metric to a constant 1 per
	// https://www.robustperception.io/exposing-the-software-version-to-prometheus
	m.Set(1)
	return nil
}

func (r *metricRegistry) addPolicyCountCallback(service string, f func() int64) error {
	if r.policyCount == nil {
		return nil
	}
	err := r.policyCount.UpsertEntry(f, metricdata.NewLabelValue(service))
	if err != nil {
		return fmt.Errorf("failed to get policy count metric: %w", err)
	}
	return nil
}

func (r *metricRegistry) setConfigChecksum(service string, configName string, checksum uint64) error {
	if r.configChecksum == nil {
		return nil
	}
	m, err := r.configChecksum.GetEntry(metricdata.NewLabelValue(service), metricdata.NewLabelValue(configName))
	if err != nil {
		return fmt.Errorf("failed to get config checksum metric: %w", err)
	}
	m.Set(float64(checksum))
	return nil
}

func (r *metricRegistry) addInt64DerivedGaugeMetric(name, desc, service string, f func() int64) error {
	m, err := r.registry.AddInt64DerivedGauge(name, metric.WithDescription(desc),
		metric.WithLabelKeys(metrics.ServiceLabel))
	if err != nil {
		return fmt.Errorf("failed to register metric: %w", err)
	}

	err = m.UpsertEntry(f, metricdata.NewLabelValue(service))
	if err != nil {
		return fmt.Errorf("failed to update metric: %w", err)
	}
	return nil
}

func (r *metricRegistry) addInt64DerivedCumulativeMetric(name, desc, service string, f func() int64) error {
	m, err := r.registry.AddInt64DerivedCumulative(name, metric.WithDescription(desc),
		metric.WithLabelKeys(metrics.ServiceLabel))
	if err != nil {
		return fmt.Errorf("failed to register metric: %w", err)
	}

	err = m.UpsertEntry(f, metricdata.NewLabelValue(service))
	if err != nil {
		return fmt.Errorf("failed to update metric: %w", err)
	}

	return nil
}
