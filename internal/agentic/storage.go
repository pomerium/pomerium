package agentic

import (
	"context"

	"google.golang.org/protobuf/types/known/structpb"

	"github.com/pomerium/pomerium/internal/log"
	oauth21proto "github.com/pomerium/pomerium/internal/oauth21/gen"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

// SessionID is the databroker session id for a run. The "agentic-" prefix keeps
// it disjoint from MCP ("mcp-...") and JWT (SHA1-derived) session ids.
func SessionID(runID string) string { return "agentic-" + runID }

// ActClaimPrefix namespaces the executor identity a run is sealed to when it is
// written onto the run's session (buildRunSession). Route PPL reads these as
// act.<path>, and the client-bindings page reads them back to show the user
// which workload is acting as them — so the prefix is a constant, not a literal
// repeated at each end.
const ActClaimPrefix = "act."

// GetRun reads a run record by id. The caller passes the direct databroker
// client (not a cached querier) so revocation is authoritative per request.
func GetRun(ctx context.Context, client databroker.DataBrokerServiceClient, id string) (*oauth21proto.AgenticRun, error) {
	res, err := client.Get(ctx, &databroker.GetRequest{
		Type: protoutil.GetTypeURL(new(oauth21proto.AgenticRun)),
		Id:   id,
	})
	if err != nil {
		return nil, err
	}
	run := new(oauth21proto.AgenticRun)
	if err := res.GetRecord().GetData().UnmarshalTo(run); err != nil {
		return nil, err
	}
	return run, nil
}

// PutRun stores (creates or updates) a run record.
func PutRun(ctx context.Context, client databroker.DataBrokerServiceClient, run *oauth21proto.AgenticRun) error {
	data := protoutil.NewAny(run)
	_, err := client.Put(ctx, &databroker.PutRequest{Records: []*databroker.Record{{
		Id:   run.GetId(),
		Data: data,
		Type: data.GetTypeUrl(),
	}}})
	return err
}

// sealLookupLimit bounds how many runs the seal lookup considers for one
// executor. It must never be zero: ApplyOffsetAndLimit reads a zero limit as
// "take zero", not "no limit", which would turn every exchange into a permanent
// authorization_pending with nothing logged anywhere.
const sealLookupLimit = 10

// QueryRunByBoundClaimsIndex resolves the run sealed to the executor whose
// canonical bound-claims index is boundClaimsIndex, using the databroker's native
// secondary index on AgenticRun.bound_claims_index (registered in
// setupRequiredIndex). It returns nil (with a nil error) when no run is sealed to
// that executor — the normal case during the launch race, before the summoner has
// created the run.
//
// The presenting workload token reproduces boundClaimsIndex from its own claims
// via sealIndexKey, so a pod resolves its run from its identity alone — no run_id
// is ever an input. The index is a lookup only: the authoritative instance
// seal-match still runs on the resolved run at bind.
//
// One executor can carry more than one run, since an abandoned run nobody ever
// approved is an ordinary ending. Plain newest-wins would then let a later PENDING
// record shadow a live approved one — the next poll would resolve the pending
// record and a human's approval would become permanently unreachable — so an
// approved run wins, and the newest wins among equals.
func QueryRunByBoundClaimsIndex(ctx context.Context, client databroker.DataBrokerServiceClient, boundClaimsIndex string) (*oauth21proto.AgenticRun, error) {
	res, err := client.Query(ctx, &databroker.QueryRequest{
		Type:  protoutil.GetTypeURL(new(oauth21proto.AgenticRun)),
		Limit: sealLookupLimit,
		Filter: &structpb.Struct{Fields: map[string]*structpb.Value{
			"bound_claims_index": structpb.NewStringValue(boundClaimsIndex),
		}},
	})
	if err != nil {
		return nil, err
	}
	if total := res.GetTotalCount(); total > sealLookupLimit {
		// TotalCount is the pre-limit count, so this says the window did not cover
		// every candidate and the selection below may not have seen the right one.
		log.Ctx(ctx).Warn().Int64("total", total).Int("considered", sealLookupLimit).
			Msg("agentic: more runs are sealed to one executor than the seal lookup considers")
	}

	var best *oauth21proto.AgenticRun
	for _, rec := range res.GetRecords() {
		run := new(oauth21proto.AgenticRun)
		if err := rec.GetData().UnmarshalTo(run); err != nil {
			return nil, err
		}
		if betterSealCandidate(best, run) {
			best = run
		}
	}
	return best, nil
}

// betterSealCandidate reports whether candidate should replace current as the run
// an executor resolves to.
func betterSealCandidate(current, candidate *oauth21proto.AgenticRun) bool {
	switch {
	case current == nil:
		return true
	case IsApproved(current) != IsApproved(candidate):
		return IsApproved(candidate)
	default:
		return candidate.GetCreatedAt().AsTime().After(current.GetCreatedAt().AsTime())
	}
}

// IsApproved reports whether a human has approved this run.
//
// Only an explicit APPROVED counts. Proto3's zero value means no state was ever
// written, which cannot be the result of somebody consenting — treating it as
// approved is the fail-open this replaced.
func IsApproved(run *oauth21proto.AgenticRun) bool {
	return run.GetState() == oauth21proto.AgenticRunState_AGENTIC_RUN_STATE_APPROVED
}
