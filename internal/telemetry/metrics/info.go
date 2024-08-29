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

		IdentityManagerLastUserRefreshErrorTimestampView,
		IdentityManagerLastUserRefreshErrorView,
		IdentityManagerLastUserRefreshSuccessTimestampView,
		IdentityManagerLastUserRefreshSuccessView,

		IdentityManagerLastUserGroupRefreshErrorTimestampView,
		IdentityManagerLastUserGroupRefreshErrorView,
		IdentityManagerLastUserGroupRefreshSuccessTimestampView,
		IdentityManagerLastUserGroupRefreshSuccessView,

		IdentityManagerLastSessionRefreshErrorTimestampView,
		IdentityManagerLastSessionRefreshErrorView,
		IdentityManagerLastSessionRefreshSuccessTimestampView,
		IdentityManagerLastSessionRefreshSuccessView,

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

	identityManagerLastUserRefreshSuccessTimestamp = stats.Int64(
		metrics.IdentityManagerLastUserRefreshSuccessTimestamp,
		"Timestamp of last successful directory user refresh success",
		stats.UnitSeconds,
	)
	identityManagerLastUserRefreshErrorTimestamp = stats.Int64(
		metrics.IdentityManagerLastUserRefreshErrorTimestamp,
		"Timestamp of last directory user refresh error",
		stats.UnitSeconds,
	)
	identityManagerLastUserRefreshSuccess = stats.Int64(
		metrics.IdentityManagerLastUserRefreshSuccess,
		"Total successful directory user refresh requests",
		stats.UnitDimensionless,
	)
	identityManagerLastUserRefreshError = stats.Int64(
		metrics.IdentityManagerLastUserRefreshError,
		"Total successful directory user refresh errors",
		stats.UnitDimensionless,
	)

	identityManagerLastUserGroupRefreshSuccessTimestamp = stats.Int64(
		metrics.IdentityManagerLastUserGroupRefreshSuccessTimestamp,
		"Timestamp of last successful user group refresh success",
		stats.UnitSeconds,
	)
	identityManagerLastUserGroupRefreshErrorTimestamp = stats.Int64(
		metrics.IdentityManagerLastUserGroupRefreshErrorTimestamp,
		"Timestamp of last directory user group refresh error",
		stats.UnitSeconds,
	)
	identityManagerLastUserGroupRefreshSuccess = stats.Int64(
		metrics.IdentityManagerLastUserGroupRefreshSuccess,
		"Total successful directory user group refresh requests",
		stats.UnitDimensionless,
	)
	identityManagerLastUserGroupRefreshError = stats.Int64(
		metrics.IdentityManagerLastUserGroupRefreshError,
		"Total successful directory user refresh errors",
		stats.UnitDimensionless,
	)

	identityManagerLastSessionRefreshSuccessTimestamp = stats.Int64(
		metrics.IdentityManagerLastSessionRefreshSuccessTimestamp,
		"Timestamp of last successful session refresh success",
		stats.UnitSeconds,
	)
	identityManagerLastSessionRefreshErrorTimestamp = stats.Int64(
		metrics.IdentityManagerLastSessionRefreshErrorTimestamp,
		"Timestamp of last session refresh error",
		stats.UnitSeconds,
	)
	identityManagerLastSessionRefreshSuccess = stats.Int64(
		metrics.IdentityManagerLastSessionRefreshSuccess,
		"Total successful session refresh requests",
		stats.UnitDimensionless,
	)
	identityManagerLastSessionRefreshError = stats.Int64(
		metrics.IdentityManagerLastSessionRefreshError,
		"Total successful session refresh errors",
		stats.UnitDimensionless,
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

	// IdentityManagerLastUserRefreshSuccessView contains successful user refresh counter
	IdentityManagerLastUserRefreshSuccessView = &view.View{
		Name:        identityManagerLastUserRefreshSuccess.Name(),
		Description: identityManagerLastUserRefreshSuccess.Description(),
		Measure:     identityManagerLastUserRefreshSuccess,
		Aggregation: view.Count(),
	}
	// IdentityManagerLastUserRefreshErrorView contains user refresh errors counter
	IdentityManagerLastUserRefreshErrorView = &view.View{
		Name:        identityManagerLastUserRefreshError.Name(),
		Description: identityManagerLastUserRefreshError.Description(),
		Measure:     identityManagerLastUserRefreshError,
		Aggregation: view.Count(),
	}
	// IdentityManagerLastUserRefreshSuccessTimestampView contains successful user refresh counter
	IdentityManagerLastUserRefreshSuccessTimestampView = &view.View{
		Name:        identityManagerLastUserRefreshSuccessTimestamp.Name(),
		Description: identityManagerLastUserRefreshSuccessTimestamp.Description(),
		Measure:     identityManagerLastUserRefreshSuccessTimestamp,
		Aggregation: view.LastValue(),
	}
	// IdentityManagerLastUserRefreshErrorTimestampView contains user refresh errors counter
	IdentityManagerLastUserRefreshErrorTimestampView = &view.View{
		Name:        identityManagerLastUserRefreshErrorTimestamp.Name(),
		Description: identityManagerLastUserRefreshErrorTimestamp.Description(),
		Measure:     identityManagerLastUserRefreshErrorTimestamp,
		Aggregation: view.LastValue(),
	}

	// IdentityManagerLastUserGroupRefreshSuccessView contains successful user group refresh counter
	IdentityManagerLastUserGroupRefreshSuccessView = &view.View{
		Name:        identityManagerLastUserGroupRefreshSuccess.Name(),
		Description: identityManagerLastUserGroupRefreshSuccess.Description(),
		Measure:     identityManagerLastUserGroupRefreshSuccess,
		Aggregation: view.Count(),
	}
	// IdentityManagerLastUserGroupRefreshErrorView contains user group refresh errors counter
	IdentityManagerLastUserGroupRefreshErrorView = &view.View{
		Name:        identityManagerLastUserGroupRefreshError.Name(),
		Description: identityManagerLastUserGroupRefreshError.Description(),
		Measure:     identityManagerLastUserGroupRefreshError,
		Aggregation: view.Count(),
	}
	// IdentityManagerLastUserGroupRefreshSuccessTimestampView contains successful user group refresh counter
	IdentityManagerLastUserGroupRefreshSuccessTimestampView = &view.View{
		Name:        identityManagerLastUserGroupRefreshSuccessTimestamp.Name(),
		Description: identityManagerLastUserGroupRefreshSuccessTimestamp.Description(),
		Measure:     identityManagerLastUserGroupRefreshSuccessTimestamp,
		Aggregation: view.LastValue(),
	}
	// IdentityManagerLastUserGroupRefreshErrorTimestampView contains user group refresh errors counter
	IdentityManagerLastUserGroupRefreshErrorTimestampView = &view.View{
		Name:        identityManagerLastUserGroupRefreshErrorTimestamp.Name(),
		Description: identityManagerLastUserGroupRefreshErrorTimestamp.Description(),
		Measure:     identityManagerLastUserGroupRefreshErrorTimestamp,
		Aggregation: view.LastValue(),
	}

	// IdentityManagerLastSessionRefreshSuccessView contains successful user refresh counter
	IdentityManagerLastSessionRefreshSuccessView = &view.View{
		Name:        identityManagerLastSessionRefreshSuccess.Name(),
		Description: identityManagerLastSessionRefreshSuccess.Description(),
		Measure:     identityManagerLastSessionRefreshSuccess,
		Aggregation: view.Count(),
	}
	// IdentityManagerLastSessionRefreshErrorView contains user refresh errors counter
	IdentityManagerLastSessionRefreshErrorView = &view.View{
		Name:        identityManagerLastUserRefreshError.Name(),
		Description: identityManagerLastUserRefreshError.Description(),
		Measure:     identityManagerLastUserRefreshError,
		Aggregation: view.Count(),
	}
	// IdentityManagerLastSessionRefreshSuccessTimestampView contains successful session refresh counter
	IdentityManagerLastSessionRefreshSuccessTimestampView = &view.View{
		Name:        identityManagerLastSessionRefreshSuccessTimestamp.Name(),
		Description: identityManagerLastSessionRefreshSuccessTimestamp.Description(),
		Measure:     identityManagerLastSessionRefreshSuccessTimestamp,
		Aggregation: view.LastValue(),
	}
	// IdentityManagerLastSessionRefreshErrorTimestampView contains session refresh errors counter
	IdentityManagerLastSessionRefreshErrorTimestampView = &view.View{
		Name:        identityManagerLastSessionRefreshErrorTimestamp.Name(),
		Description: identityManagerLastSessionRefreshErrorTimestamp.Description(),
		Measure:     identityManagerLastSessionRefreshErrorTimestamp,
		Aggregation: view.LastValue(),
	}
)

// RecordIdentityManagerLastRefresh records that the identity manager refreshed users and groups.
func RecordIdentityManagerLastRefresh(ctx context.Context) {
	stats.Record(ctx, identityManagerLastRefresh.M(time.Now().Unix()))
}

// RecordIdentityManagerUserRefresh updates timestamp and counter for user refresh
func RecordIdentityManagerUserRefresh(ctx context.Context, err error) {
	counter := identityManagerLastUserRefreshSuccess
	ts := identityManagerLastUserRefreshSuccessTimestamp
	if err != nil {
		counter = identityManagerLastUserRefreshError
		ts = identityManagerLastUserRefreshErrorTimestamp
	}
	stats.Record(ctx,
		ts.M(time.Now().Unix()),
		counter.M(1),
	)
}

// RecordIdentityManagerUserGroupRefresh updates timestamp and counter for user group update
func RecordIdentityManagerUserGroupRefresh(ctx context.Context, err error) {
	counter := identityManagerLastUserGroupRefreshSuccess
	ts := identityManagerLastUserGroupRefreshSuccessTimestamp
	if err != nil {
		counter = identityManagerLastUserGroupRefreshError
		ts = identityManagerLastUserGroupRefreshErrorTimestamp
	}
	stats.Record(ctx,
		ts.M(time.Now().Unix()),
		counter.M(1),
	)
}

// RecordIdentityManagerSessionRefresh updates timestamp and counter for session refresh
func RecordIdentityManagerSessionRefresh(ctx context.Context, err error) {
	counter := identityManagerLastSessionRefreshSuccess
	ts := identityManagerLastSessionRefreshSuccessTimestamp
	if err != nil {
		counter = identityManagerLastSessionRefreshError
		ts = identityManagerLastSessionRefreshErrorTimestamp
	}
	stats.Record(ctx,
		ts.M(time.Now().Unix()),
		counter.M(1),
	)
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
		log.Ctx(ctx).Error().Err(err).Msg("telemetry/metrics: failed to record config version number")
	}

	if err := stats.RecordWithTags(
		context.Background(),
		[]tag.Mutator{
			tag.Insert(TagKeyService, service),
			tag.Insert(TagConfigID, configID),
		},
		configDBErrors.M(errCount),
	); err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("telemetry/metrics: failed to record config error count")
	}
}

// SetDBConfigRejected records that a certain databroker config version has been rejected
func SetDBConfigRejected(ctx context.Context, service, configID string, version uint64, err error) {
	log.Ctx(ctx).Error().Err(err).Msg("databroker: invalid config detected, ignoring")
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
			log.Ctx(ctx).Error().Err(err).Msg("telemetry/metrics: failed to record config checksum timestamp")
		}

		if err := stats.RecordWithTags(
			context.Background(),
			[]tag.Mutator{serviceTag},
			configLastReloadSuccess.M(1),
		); err != nil {
			log.Ctx(ctx).Error().Err(err).Msg("telemetry/metrics: failed to record config reload")
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
