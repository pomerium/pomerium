package metrics

import (
	"context"
	"time"

	"go.opencensus.io/stats"
	"go.opencensus.io/stats/view"
	"go.opencensus.io/tag"

	"github.com/pomerium/pomerium/internal/log"
)

var (
	// StorageViews contains opencensus views for storage system metrics
	StorageViews = []*view.View{StorageOperationDurationView}

	storageOperationDuration = stats.Int64(
		"storage_operation_duration_ms",
		"Storage operation duration in ms",
		"ms")

	// StorageOperationDurationView is an OpenCensus view that tracks storage client
	// latency by operation, result and backend
	StorageOperationDurationView = &view.View{
		Name:        storageOperationDuration.Name(),
		Description: storageOperationDuration.Description(),
		Measure:     storageOperationDuration,
		TagKeys:     []tag.Key{TagKeyStorageOperation, TagKeyStorageResult, TagKeyStorageBackend, TagKeyService},
		Aggregation: DefaultMillisecondsDistribution,
	}
)

// StorageOperationTags contains tags to apply when recording a storage operation
type StorageOperationTags struct {
	Operation string
	Error     error
	Backend   string
}

// RecordStorageOperation records the duration of a storage operation with the corresponding tags
func RecordStorageOperation(ctx context.Context, tags *StorageOperationTags, duration time.Duration) {
	result := "success"
	if tags.Error != nil {
		result = "error"
	}

	err := stats.RecordWithTags(ctx,
		[]tag.Mutator{
			tag.Upsert(TagKeyStorageOperation, tags.Operation),
			tag.Upsert(TagKeyStorageResult, result),
			tag.Upsert(TagKeyStorageBackend, tags.Backend),
			// TODO service tag does not consistently come in from RPCs.  Requires
			// follow up
			tag.Upsert(TagKeyService, "databroker"),
		},
		storageOperationDuration.M(duration.Milliseconds()),
	)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("internal/telemetry/metrics: failed to record")
	}
}
