package agentic

import (
	"context"
	"time"

	"google.golang.org/protobuf/types/known/structpb"

	agenticpb "github.com/pomerium/pomerium/internal/agentic/gen"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	idpsessionpb "github.com/pomerium/pomerium/pkg/grpc/idpsession"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/identity"
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
func GetRun(ctx context.Context, client databroker.DataBrokerServiceClient, id string) (*agenticpb.Run, error) {
	res, err := client.Get(ctx, &databroker.GetRequest{
		Type: protoutil.GetTypeURL(new(agenticpb.Run)),
		Id:   id,
	})
	if err != nil {
		return nil, err
	}
	run := new(agenticpb.Run)
	if err := res.GetRecord().GetData().UnmarshalTo(run); err != nil {
		return nil, err
	}
	return run, nil
}

// GetRunRecordVersion reads a run together with the databroker record version it
// was read at, for a caller that will write it back conditionally.
func GetRunRecordVersion(ctx context.Context, client databroker.DataBrokerServiceClient, id string) (*agenticpb.Run, uint64, error) {
	res, err := client.Get(ctx, &databroker.GetRequest{
		Type: protoutil.GetTypeURL(new(agenticpb.Run)),
		Id:   id,
	})
	if err != nil {
		return nil, 0, err
	}
	run := new(agenticpb.Run)
	if err := res.GetRecord().GetData().UnmarshalTo(run); err != nil {
		return nil, 0, err
	}
	return run, res.GetRecord().GetVersion(), nil
}

// PutRunIfUnchanged stores a run only if the stored record is still at version —
// the version the caller read it at. It reports databroker.IsRecordVersionMismatch
// when somebody else wrote the run in between, which is how approval stays
// single-use under concurrency.
func PutRunIfUnchanged(ctx context.Context, client databroker.DataBrokerServiceClient, run *agenticpb.Run, version uint64) error {
	data := protoutil.NewAny(run)
	_, err := databroker.PutIfMatchVersion(ctx, client, &databroker.Record{
		Id:      run.GetId(),
		Data:    data,
		Type:    data.GetTypeUrl(),
		Version: version,
	})
	return err
}

// PutRun stores (creates or updates) a run record.
func PutRun(ctx context.Context, client databroker.DataBrokerServiceClient, run *agenticpb.Run) error {
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
//
// The databroker applies the limit BEFORE the selection below runs, so the
// window is not a performance knob — a live approved run falling outside it is
// silently shadowed by a pending one and a human's approval becomes
// unreachable. The bound is therefore set far above what one executor can
// plausibly accumulate rather than at a tidy page size: the seal index includes
// kubernetes.io.pod.uid (see sealIndexKey), so these are the runs summoned by a
// single pod, and a pod reaching this many is pathological rather than busy.
const sealLookupLimit = 200

// QueryRunByBoundClaimsIndex resolves the run sealed to the executor whose
// canonical bound-claims index is boundClaimsIndex, using the databroker's native
// secondary index on agentic.Run.bound_claims_index (registered in
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
func QueryRunByBoundClaimsIndex(ctx context.Context, client databroker.DataBrokerServiceClient, boundClaimsIndex string) (*agenticpb.Run, error) {
	res, err := client.Query(ctx, &databroker.QueryRequest{
		Type:  protoutil.GetTypeURL(new(agenticpb.Run)),
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
		// An approved run may now be unreachable, which is a fault rather than a
		// slow path: log it as one.
		log.Ctx(ctx).Error().Int64("total", total).Int("considered", sealLookupLimit).
			Str("bound_claims_index", boundClaimsIndex).
			Msg("agentic: more runs are sealed to one executor than the seal lookup considers; an approved run may be unreachable")
	}

	var best *agenticpb.Run
	for _, rec := range res.GetRecords() {
		run := new(agenticpb.Run)
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
func betterSealCandidate(current, candidate *agenticpb.Run) bool {
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
func IsApproved(run *agenticpb.Run) bool {
	return run.GetState() == agenticpb.RunState_RUN_STATE_APPROVED
}

// buildRunSession issues the run's session.Session from the approver's IDPSession
// and stamps the run's identity onto it. It is shared by approval (which creates
// the session as a bound dependent) and every /token mint (which refreshes it),
// so both write an identical record shape.
//
// Via idpsession.IssueSession the session carries the approver's upstream tokens
// and IdP claims — the identity manager's reconciler keeps them fresh and deletes
// the session when the IDPSession dies — while the run-specific claims (sub,
// run_id, act.<sealed executor claim>) are what authorize evaluates. The run's
// own sub overrides the IdP subject; RefreshDisabled keeps any legacy per-session
// refresher from ever presenting the copied upstream refresh token.
func buildRunSession(idpSess *idpsessionpb.IDPSession, run *agenticpb.Run, now time.Time) *session.Session {
	s := idpsessionpb.IssueSession(SessionID(run.GetId()), idpSess, now, 0)
	s.ExpiresAt = run.GetExpiresAt()
	s.RefreshDisabled = true
	claims := identity.FlattenedClaims{
		"sub":    {run.GetSub()},
		"run_id": {run.GetId()},
	}
	for k, vs := range identity.NewFlattenedClaimsFromPB(run.GetBoundClaims()) {
		claims[ActClaimPrefix+k] = vs
	}
	s.AddClaims(claims)
	return s
}

// approverSubject is the approver's subject, or "" if nobody approved the run.
func approverSubject(run *agenticpb.Run) string {
	if !IsApproved(run) {
		return ""
	}
	return run.GetSub()
}

// stateString renders a run's state for the API and the consent page.
func stateString(run *agenticpb.Run) string {
	if IsApproved(run) {
		return "approved"
	}
	return "pending_approval"
}
