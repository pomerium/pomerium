package metrics

import (
	"context"

	"go.opencensus.io/stats"
	"go.opencensus.io/stats/view"
	"go.opencensus.io/tag"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/metrics"
)

var (
	EnvoyViews = []*view.View{
		EnvoyOverloadActionStateView,
		EnvoyOverloadActionThresholdView,
		EnvoyCgroupMemorySaturationView,
	}

	EnvoyOverloadActionState = stats.Int64(
		metrics.EnvoyOverloadActionState,
		"Current state of envoy overload actions by cgroup",
		stats.UnitDimensionless,
	)

	EnvoyOverloadActionThreshold = stats.Float64(
		metrics.EnvoyOverloadActionThreshold,
		"Injected memory usage minimum thresholds for envoy overload actions",
		stats.UnitDimensionless,
	)

	EnvoyCgroupMemorySaturation = stats.Float64(
		metrics.EnvoyCgroupMemorySaturation,
		"Memory usage percent (0.0-1.0) of the cgroup in which envoy is running",
		stats.UnitDimensionless,
	)

	EnvoyOverloadActionStateView = &view.View{
		Name:        EnvoyOverloadActionState.Name(),
		Description: EnvoyOverloadActionState.Description(),
		TagKeys:     []tag.Key{TagKeyCgroup, TagKeyActionName},
		Measure:     EnvoyOverloadActionState,
		Aggregation: view.LastValue(),
	}

	EnvoyOverloadActionThresholdView = &view.View{
		Name:        EnvoyOverloadActionThreshold.Name(),
		Description: EnvoyOverloadActionThreshold.Description(),
		TagKeys:     []tag.Key{TagKeyActionName},
		Measure:     EnvoyOverloadActionThreshold,
		Aggregation: view.LastValue(),
	}

	EnvoyCgroupMemorySaturationView = &view.View{
		Name:        EnvoyCgroupMemorySaturation.Name(),
		Description: EnvoyCgroupMemorySaturation.Description(),
		TagKeys:     []tag.Key{TagKeyCgroup},
		Measure:     EnvoyCgroupMemorySaturation,
		Aggregation: view.LastValue(),
	}
)

type EnvoyOverloadActionStateTags struct {
	Cgroup     string
	ActionName string
}

func RecordEnvoyOverloadActionState(ctx context.Context, tags EnvoyOverloadActionStateTags, state int64) {
	err := stats.RecordWithTags(ctx,
		[]tag.Mutator{
			tag.Upsert(TagKeyCgroup, tags.Cgroup),
			tag.Upsert(TagKeyActionName, tags.ActionName),
		},
		EnvoyOverloadActionState.M(state),
	)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("internal/telemetry/metrics: failed to record")
	}
}

func RecordEnvoyOverloadActionThreshold(ctx context.Context, actionName string, threshold float64) {
	err := stats.RecordWithTags(ctx,
		[]tag.Mutator{
			tag.Upsert(TagKeyActionName, actionName),
		},
		EnvoyOverloadActionThreshold.M(threshold),
	)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("internal/telemetry/metrics: failed to record")
	}
}

func RecordEnvoyCgroupMemorySaturation(ctx context.Context, cgroup string, percent float64) {
	err := stats.RecordWithTags(ctx,
		[]tag.Mutator{
			tag.Upsert(TagKeyCgroup, cgroup),
		},
		EnvoyCgroupMemorySaturation.M(percent),
	)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("internal/telemetry/metrics: failed to record")
	}
}
