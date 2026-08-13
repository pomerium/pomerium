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
	// IdpSessionViews contains the views for the canonical upstream identity
	// provider session.
	IdpSessionViews = []*view.View{
		IdpSessionPresentationsView,
		IdpSessionServedFromRecordView,
		IdpSessionRecordsRetiredView,
		IdpSessionCallerBudgetTimeoutsView,
	}

	idpSessionPresentations = stats.Int64(
		metrics.IdpSessionPresentations,
		"Upstream refresh tokens presented to an identity provider",
		stats.UnitDimensionless,
	)
	idpSessionServedFromRecord = stats.Int64(
		metrics.IdpSessionServedFromRecord,
		"Liveness answers served from the canonical record without contacting the identity provider",
		stats.UnitDimensionless,
	)
	idpSessionRecordsRetired = stats.Int64(
		metrics.IdpSessionRecordsRetired,
		"Canonical upstream sessions retired",
		stats.UnitDimensionless,
	)
	idpSessionCallerBudgetTimeouts = stats.Int64(
		metrics.IdpSessionCallerBudgetTimeouts,
		"Callers that stopped waiting while a detached refresh attempt ran on",
		stats.UnitDimensionless,
	)

	// IdpSessionPresentationsView counts presentations by outcome. It is the
	// load a deployment puts on its identity provider, and the ratio against
	// IdpSessionServedFromRecordView is what the shared record buys.
	IdpSessionPresentationsView = &view.View{
		Name:        idpSessionPresentations.Name(),
		Description: idpSessionPresentations.Description(),
		Measure:     idpSessionPresentations,
		TagKeys:     []tag.Key{TagKeyIdpSessionOutcome},
		Aggregation: view.Count(),
	}
	// IdpSessionServedFromRecordView counts answers that cost no identity
	// provider call.
	IdpSessionServedFromRecordView = &view.View{
		Name:        idpSessionServedFromRecord.Name(),
		Description: idpSessionServedFromRecord.Description(),
		Measure:     idpSessionServedFromRecord,
		Aggregation: view.Count(),
	}
	// IdpSessionRecordsRetiredView counts retirements by reason. Every one of
	// them ends every session and MCP client of that user until the user signs
	// in again, so a rise here is the signal an operator most needs.
	IdpSessionRecordsRetiredView = &view.View{
		Name:        idpSessionRecordsRetired.Name(),
		Description: idpSessionRecordsRetired.Description(),
		Measure:     idpSessionRecordsRetired,
		TagKeys:     []tag.Key{TagKeyIdpSessionDeadReason},
		Aggregation: view.Count(),
	}
	// IdpSessionCallerBudgetTimeoutsView counts callers told to retry while the
	// work they started ran on. A sustained rate means the identity provider is
	// slower than the request budget allows for.
	IdpSessionCallerBudgetTimeoutsView = &view.View{
		Name:        idpSessionCallerBudgetTimeouts.Name(),
		Description: idpSessionCallerBudgetTimeouts.Description(),
		Measure:     idpSessionCallerBudgetTimeouts,
		Aggregation: view.Count(),
	}
)

// RecordIdpSessionPresentation records one presentation of an upstream refresh
// token, labeled by how it ended.
func RecordIdpSessionPresentation(ctx context.Context, outcome string) {
	err := stats.RecordWithTags(ctx,
		[]tag.Mutator{tag.Upsert(TagKeyIdpSessionOutcome, outcome)},
		idpSessionPresentations.M(1),
	)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("internal/telemetry/metrics: failed to record")
	}
}

// RecordIdpSessionServedFromRecord records a liveness answer that cost no
// identity provider call.
func RecordIdpSessionServedFromRecord(ctx context.Context) {
	stats.Record(ctx, idpSessionServedFromRecord.M(1))
}

// RecordIdpSessionRecordRetired records a canonical upstream session being
// retired, labeled by why.
func RecordIdpSessionRecordRetired(ctx context.Context, deadReason string) {
	err := stats.RecordWithTags(ctx,
		[]tag.Mutator{tag.Upsert(TagKeyIdpSessionDeadReason, deadReason)},
		idpSessionRecordsRetired.M(1),
	)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("internal/telemetry/metrics: failed to record")
	}
}

// RecordIdpSessionCallerBudgetTimeout records a caller that stopped waiting
// while the attempt it started ran on.
func RecordIdpSessionCallerBudgetTimeout(ctx context.Context) {
	stats.Record(ctx, idpSessionCallerBudgetTimeouts.M(1))
}
