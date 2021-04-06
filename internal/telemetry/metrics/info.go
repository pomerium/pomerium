package metrics

import (
	"context"
	"fmt"
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
		ConfigDbVersionView,
		ConfigDbErrorsView,
	}

	configLastReload = stats.Int64(
		metrics.ConfigLastReloadTimestampSeconds,
		"Timestamp of last successful config reload",
		stats.UnitSeconds)
	configDbVersion = stats.Int64(
		metrics.ConfigDbVersion,
		metrics.ConfigDbVersionHelp,
		stats.UnitDimensionless,
	)
	configDbErrors = stats.Int64(
		metrics.ConfigDbErrors,
		metrics.ConfigDbErrorsHelp,
		stats.UnitDimensionless,
	)
	configLastReloadSuccess = stats.Int64(
		metrics.ConfigLastReloadSuccess,
		"Returns 1 if last reload was successful",
		stats.UnitDimensionless)
	identityManagerLastRefresh = stats.Int64(
		metrics.IdentityManagerLastRefreshTimestamp,
		"Timestamp of last directory refresh",
		"seconds",
	)

	// ConfigDbVersionView contains last databroker config version that was processed
	ConfigDbVersionView = &view.View{
		Name:        configDbVersion.Name(),
		Description: configDbVersion.Description(),
		Measure:     configDbVersion,
		TagKeys:     []tag.Key{TagKeyService, TagConfigID},
		Aggregation: view.LastValue(),
	}

	ConfigDbErrorsView = &view.View{
		Name:        configDbErrors.Name(),
		Description: configDbErrors.Description(),
		Measure:     configDbErrors,
		TagKeys:     []tag.Key{TagKeyService, TagConfigID},
		Aggregation: view.LastValue(),
	}

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

// SetDbConfigInfo records status, databroker version and error count while parsing
// the configuration from a databroker
func SetDbConfigInfo(service, configID string, version uint64, errCount int64) {
	log.Info().
		Str("service", service).
		Str("config_id", configID).
		Uint64("version", version).
		Int64("err_count", errCount).
		Msg("set db config info")

	if err := stats.RecordWithTags(
		context.Background(),
		[]tag.Mutator{
			tag.Insert(TagKeyService, service),
			tag.Insert(TagConfigID, configID),
		},
		configDbVersion.M(int64(version)),
	); err != nil {
		log.Error().Err(err).Msg("telemetry/metrics: failed to record config version number")
	}

	if err := stats.RecordWithTags(
		context.Background(),
		[]tag.Mutator{
			tag.Insert(TagKeyService, service),
			tag.Insert(TagConfigID, configID),
		},
		configDbErrors.M(errCount),
	); err != nil {
		log.Error().Err(err).Msg("telemetry/metrics: failed to record config error count")
	}

}

// SetDbConfigInfo records that a certain databroker config version has been rejected
func SetDbConfigRejected(service, configID string, version uint64, err error) {
	log.Warn().Err(err).Msg("databroker: invalid config detected, ignoring")
	SetDbConfigInfo(service, configID, version, -1)
}

// SetConfigInfo records the status, checksum and timestamp of a configuration
// reload. You must register InfoViews or the related config views before calling
func SetConfigInfo(service, configName string, checksum uint64, success bool) {
	if success {
		registry.setConfigChecksum(service, configName, checksum)

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
	log.Info().
		Str("service", service).
		Str("config", configName).
		Str("checksum", fmt.Sprintf("%x", checksum)).
		Msg("config: updated config")
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

// AddPolicyCountCallback sets the function to call when exporting the
// policy count metric.   You must call RegisterInfoMetrics to have this
// exported
func AddPolicyCountCallback(service string, f func() int64) {
	registry.addPolicyCountCallback(service, f)
}
