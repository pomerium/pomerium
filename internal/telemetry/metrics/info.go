package metrics

import (
	"context"
	"time"

	"go.opencensus.io/metric/metricproducer"
	"go.opencensus.io/stats"
	"go.opencensus.io/stats/view"
	"go.opencensus.io/tag"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/metrics"
)

var (
	// InfoViews contains opencensus views for informational metrics about
	// pomerium itself.
	InfoViews = []*view.View{
		ConfigLastReloadView,
		ConfigLastReloadSuccessView,
		IdentityManagerLastRefreshView,
	}

	configLastReload = stats.Int64(
		metrics.ConfigLastReloadTimestampSeconds,
		"Timestamp of last successful config reload",
		"seconds")
	configLastReloadSuccess = stats.Int64(
		metrics.ConfigLastReloadSuccess,
		"Returns 1 if last reload was successful",
		"1")
	identityManagerLastRefresh = stats.Int64(
		metrics.IdentityManagerLastRefreshTimestamp,
		"Timestamp of last directory refresh",
		"seconds",
	)

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

	// IdentityManagerLastRefreshView contains the timestamp the identity manager
	// was last refreshed, labeled by service.
	IdentityManagerLastRefreshView = &view.View{
		Name:        identityManagerLastRefresh.Name(),
		Description: identityManagerLastRefresh.Description(),
		Measure:     identityManagerLastRefresh,
		Aggregation: view.LastValue(),
	}
)

// RecordIdentityManagerLastRefresh records that the identity manager refreshed users and groups.
func RecordIdentityManagerLastRefresh() {
	stats.Record(context.Background(), identityManagerLastRefresh.M(time.Now().Unix()))
}

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

// SetBuildInfo records the pomerium build info. You must call RegisterInfoMetrics to
// have this exported
func SetBuildInfo(service, hostname string) {
	registry.setBuildInfo(service, hostname)
}

// RegisterInfoMetrics registers non-view based metrics registry globally for export
func RegisterInfoMetrics() {
	metricproducer.GlobalManager().AddProducer(registry.registry)
}

// SetConfigChecksum creates the configuration checksum metric.  You must call RegisterInfoMetrics to
// have this exported
func SetConfigChecksum(service string, checksum uint64) {
	registry.setConfigChecksum(service, checksum)
}

// AddPolicyCountCallback sets the function to call when exporting the
// policy count metric.   You must call RegisterInfoMetrics to have this
// exported
func AddPolicyCountCallback(service string, f func() int64) {
	registry.addPolicyCountCallback(service, f)
}
