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
		ConfigDBVersionView,
		ConfigDBErrorsView,
	}

	configLastReload = stats.Int64(
		metrics.ConfigLastReloadTimestampSeconds,
		"Timestamp of last successful config reload",
		stats.UnitSeconds)
	configDBVersion = stats.Int64(
		metrics.ConfigDBVersion,
		metrics.ConfigDBVersionHelp,
		stats.UnitDimensionless,
	)
	configDBErrors = stats.Int64(
		metrics.ConfigDBErrors,
		metrics.ConfigDBErrorsHelp,
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

	// ConfigDBVersionView contains last databroker config version that was processed
	ConfigDBVersionView = &view.View{
		Name:        configDBVersion.Name(),
		Description: configDBVersion.Description(),
		Measure:     configDBVersion,
		TagKeys:     []tag.Key{TagKeyService, TagConfigID},
		Aggregation: view.LastValue(),
	}

	// ConfigDBErrorsView contains list of errors encountered while parsing this databroker config
	ConfigDBErrorsView = &view.View{
		Name:        configDBErrors.Name(),
		Description: configDBErrors.Description(),
		Measure:     configDBErrors,
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

// SetDBConfigInfo records status, databroker version and error count while parsing
// the configuration from a databroker
func SetDBConfigInfo(ctx context.Context, service, configID string, version uint64, errCount int64) {
	log.Info(ctx).
		Str("service", service).
		Str("config_id", configID).
		Uint64("version", version).
		Int64("err_count", errCount).
		Msg("set db config info")

	if err := stats.RecordWithTags(
		ctx,
		[]tag.Mutator{
			tag.Insert(TagKeyService, service),
			tag.Insert(TagConfigID, configID),
		},
		configDBVersion.M(int64(version)),
	); err != nil {
		log.Error(ctx).Err(err).Msg("telemetry/metrics: failed to record config version number")
	}

	if err := stats.RecordWithTags(
		context.Background(),
		[]tag.Mutator{
			tag.Insert(TagKeyService, service),
			tag.Insert(TagConfigID, configID),
		},
		configDBErrors.M(errCount),
	); err != nil {
		log.Error(ctx).Err(err).Msg("telemetry/metrics: failed to record config error count")
	}
}

// SetDBConfigRejected records that a certain databroker config version has been rejected
func SetDBConfigRejected(ctx context.Context, service, configID string, version uint64, err error) {
	log.Warn(ctx).Err(err).Msg("databroker: invalid config detected, ignoring")
	SetDBConfigInfo(ctx, service, configID, version, -1)
}

// SetConfigInfo records the status, checksum and timestamp of a configuration
// reload. You must register InfoViews or the related config views before calling
func SetConfigInfo(ctx context.Context, service, configName string, checksum uint64, success bool) {
	if success {
		registry.setConfigChecksum(service, configName, checksum)

		serviceTag := tag.Insert(TagKeyService, service)
		if err := stats.RecordWithTags(
			context.Background(),
			[]tag.Mutator{serviceTag},
			configLastReload.M(time.Now().Unix()),
		); err != nil {
			log.Error(ctx).Err(err).Msg("telemetry/metrics: failed to record config checksum timestamp")
		}

		if err := stats.RecordWithTags(
			context.Background(),
			[]tag.Mutator{serviceTag},
			configLastReloadSuccess.M(1),
		); err != nil {
			log.Error(ctx).Err(err).Msg("telemetry/metrics: failed to record config reload")
		}
	} else {
		stats.Record(context.Background(), configLastReloadSuccess.M(0))
	}
	log.Info(ctx).
		Str("service", service).
		Str("config", configName).
		Str("checksum", fmt.Sprintf("%x", checksum)).
		Msg("config: updated config")
}

// SetBuildInfo records the pomerium build info. You must call RegisterInfoMetrics to
// have this exported
func SetBuildInfo(service, hostname, envoyVersion string) {
	registry.setBuildInfo(service, hostname, envoyVersion)
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
