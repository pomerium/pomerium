package idpsession

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/btree"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/log"
	oauth21 "github.com/pomerium/pomerium/internal/oauth21/gen"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/idpsession"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
)

const (
	idpSessionTypeURL      = "type.googleapis.com/idpsession.IDPSession"
	bindingTypeURL         = "type.googleapis.com/idpsession.Binding"
	sessionTypeURL         = "type.googleapis.com/session.Session"
	userTypeURL            = "type.googleapis.com/user.User"
	mcpRefreshTokenTypeURL = "type.googleapis.com/oauth21.MCPRefreshToken"
)

const (
	idpSessionGracePeriod = time.Hour
	bindingGracePeriod    = time.Hour
)

const maxPatchRequestSize = 1024 * 1024

type ChangeSetType = uint8

// there's an implicit ordering here representing priority of operations (delete > revoke > propagate)
const (
	// changePropagate copies idpsession state onto the dependent records bound to it
	changePropagate ChangeSetType = iota + 1
	// changeRevoke marks bindings revoked and deletes the records bound to them
	changeRevoke
	// changeDelete removes a record once its revocation grace period has elapsed
	changeDelete
)

func ChangeSetTypeStr(cst ChangeSetType) string {
	switch cst {
	case changePropagate:
		return "propagate"
	case changeRevoke:
		return "revoke"
	case changeDelete:
		return "delete"
	}
	return "UNKNOWN"
}

type boundRef struct {
	typeURL      string
	idpSessionID string
	// state must be the state reported from the storage backend, and not
	// track a pending state.
	state idpsession.BindingState
}

// A changeSetStore keeps track of idpsession.IDPSession and the records they are bound to through
// idpsession.Binding
type changeSetStore struct {
	*sync.Mutex

	// holds state
	idpSessions map[string]*idpsession.IDPSession

	// binding id -> references + state
	bindingsRef map[string]boundRef

	// idpsession id -> binding id
	bindings map[string]map[string]struct{}
}

func newChangeSetStore() *changeSetStore {
	return &changeSetStore{
		Mutex:       &sync.Mutex{},
		idpSessions: map[string]*idpsession.IDPSession{},
		bindingsRef: map[string]boundRef{},
		bindings:    map[string]map[string]struct{}{},
	}
}

func (s *changeSetStore) reset() {
	s.Lock()
	defer s.Unlock()
	s.idpSessions = map[string]*idpsession.IDPSession{}
	s.bindingsRef = map[string]boundRef{}
	s.bindings = map[string]map[string]struct{}{}
}

func (s *changeSetStore) putIDPSession(sess *idpsession.IDPSession) {
	s.Lock()
	defer s.Unlock()
	s.idpSessions[sess.GetId()] = sess
}

func (s *changeSetStore) deleteIDPSession(id string) {
	s.Lock()
	defer s.Unlock()
	delete(s.idpSessions, id)
}

// implements idpSessionGetter
func (s *changeSetStore) GetIDPSession(id string) *idpsession.IDPSession {
	s.Lock()
	defer s.Unlock()
	sess, ok := s.idpSessions[id]
	if !ok {
		return nil
	}
	return proto.CloneOf(sess)
}

func (s *changeSetStore) putBinding(binding *idpsession.Binding) {
	s.Lock()
	defer s.Unlock()
	idpSessionID := binding.GetIdpSessionId()
	if _, ok := s.bindings[idpSessionID]; !ok {
		s.bindings[idpSessionID] = map[string]struct{}{}
	}
	s.bindings[idpSessionID][binding.GetId()] = struct{}{}
	s.bindingsRef[binding.GetId()] = boundRef{
		typeURL:      binding.GetTypeUrl(),
		idpSessionID: idpSessionID,
		state:        binding.GetState(),
	}
}

func (s *changeSetStore) deleteBinding(binding *idpsession.Binding) {
	s.Lock()
	defer s.Unlock()
	ref, ok := s.bindingsRef[binding.GetId()]
	if !ok {
		return
	}
	delete(s.bindingsRef, binding.GetId())
	delete(s.bindings[ref.idpSessionID], binding.GetId())
	if len(s.bindings[ref.idpSessionID]) == 0 {
		delete(s.bindings, ref.idpSessionID)
	}
}

func (s *changeSetStore) bindingRevoked(bindingID string) bool {
	s.Lock()
	defer s.Unlock()
	return s.bindingsRef[bindingID].state == idpsession.BindingState_BindingState_REVOKED
}

func (s *changeSetStore) idpSessionLocked(id string) (*idpsession.IDPSession, bool) {
	sess, ok := s.idpSessions[id]
	return sess, ok
}

func (s *changeSetStore) bindingLocked(bindingID string) (boundRef, bool) {
	ref, ok := s.bindingsRef[bindingID]
	return ref, ok
}

func (s *changeSetStore) bindingsLocked(idpSessionID string) map[string]struct{} {
	return s.bindings[idpSessionID]
}

type ChangeSet struct {
	At            time.Time
	RecordID      string
	RecordTypeURL string
	changeType    ChangeSetType
}

func changeSetLess(a, b ChangeSet) bool {
	if !a.At.Equal(b.At) {
		return a.At.Before(b.At)
	}
	if a.RecordTypeURL != b.RecordTypeURL {
		return a.RecordTypeURL < b.RecordTypeURL
	}
	if a.RecordID != b.RecordID {
		return a.RecordID < b.RecordID
	}
	return a.changeType < b.changeType
}

type opType = uint8

const (
	opPatch opType = iota + 1
	opDelete
)

func OpTypeStr(ot opType) string {
	switch ot {
	case opDelete:
		return "delete"
	case opPatch:
		return "path"
	}
	return "UNKNOWN"
}

type recordKey = [2]string

type recordOp struct {
	opType opType
	record *databroker.Record
}

type recordOps map[recordKey]recordOp

func (ops recordOps) patch(key recordKey, record *databroker.Record) {
	if cur, ok := ops[key]; ok && cur.opType == opDelete {
		return
	}
	ops[key] = recordOp{opType: opPatch, record: record}
}

func (ops recordOps) delete(key recordKey, record *databroker.Record, at time.Time) {
	record.DeletedAt = timestamppb.New(at)
	ops[key] = recordOp{opType: opDelete, record: record}
}

type changeSetApplier struct {
	clientB databroker.ClientGetter
	store   *changeSetStore

	mu         sync.Mutex
	changeSets *btree.BTreeG[ChangeSet]
}

func newChangeSetApplier(clientB databroker.ClientGetter, store *changeSetStore) *changeSetApplier {
	return &changeSetApplier{
		clientB:    clientB,
		store:      store,
		changeSets: btree.NewG(2, changeSetLess),
	}
}

func (a *changeSetApplier) onUpdateIDPSession(ctx context.Context, sess *idpsession.IDPSession, at time.Time) {
	cs := ChangeSet{
		At:            at,
		RecordID:      sess.GetId(),
		RecordTypeURL: idpSessionTypeURL,
		changeType:    changePropagate,
	}
	if sess.GetState().GetState() == idpsession.UpstreamIdPSessionState_UPSTREAM_IDP_SESSION_STATE_INVALID {
		cs.changeType = changeRevoke
	}
	a.store.putIDPSession(sess)
	a.schedule(ctx, cs)
}

// onUpdateBinding is the hook called from databroker state, i.e. from the Syncer.
func (a *changeSetApplier) onUpdateBinding(ctx context.Context, binding *idpsession.Binding, at time.Time) {
	cs := ChangeSet{
		At:            at,
		RecordID:      binding.GetId(),
		RecordTypeURL: bindingTypeURL,
		changeType:    changePropagate,
	}
	if binding.GetState() == idpsession.BindingState_BindingState_REVOKED {
		cs.changeType = changeRevoke
	}
	a.store.putBinding(binding)
	a.schedule(ctx, cs)
}

// as opposed to onUpdateXXX helpers, this is a direct scheduling operation.
func (a *changeSetApplier) scheduleRevokeBinding(ctx context.Context, bindingID string, at time.Time) {
	cs := ChangeSet{
		At:            at,
		RecordID:      bindingID,
		RecordTypeURL: bindingTypeURL,
		changeType:    changeRevoke,
	}
	a.schedule(ctx, cs)
}

func (a *changeSetApplier) schedule(ctx context.Context, cs ChangeSet) {
	a.mu.Lock()
	defer a.mu.Unlock()
	log.Ctx(ctx).Trace().
		Str("id", cs.RecordID).
		Str("type-url", cs.RecordTypeURL).
		Str("change-type ", ChangeSetTypeStr(cs.changeType)).
		Time("scheduled-for", cs.At).
		Msg("scheduling identity manager reconciler update")
	a.changeSets.ReplaceOrInsert(cs)
}

func (a *changeSetApplier) reset() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.changeSets.Clear(false)
	a.store.reset()
}

func (a *changeSetApplier) ReconcileAtLocked(ctx context.Context, at time.Time) error {
	due := a.pendingAt(at)
	if len(due) == 0 {
		return nil
	}

	changeOps := recordOps{}
	for _, cs := range fastForward(due) {
		a.computeChangeSet(ctx, changeOps, cs, at)
	}

	if err := a.applyChangeSet(ctx, changeOps, at); err != nil {
		return err
	}
	a.forget(due)
	return nil
}

// pendingAt returns the change sets due at at, newest first.
func (a *changeSetApplier) pendingAt(at time.Time) []ChangeSet {
	a.mu.Lock()
	defer a.mu.Unlock()

	pending := []ChangeSet{}
	a.changeSets.DescendLessOrEqual(ChangeSet{At: at.Add(time.Nanosecond)}, func(cs ChangeSet) bool {
		pending = append(pending, cs)
		return true
	})
	return pending
}

func fastForward(change []ChangeSet) []ChangeSet {
	byRecord := make(map[recordKey]ChangeSet, len(change))
	for _, cs := range change {
		key := recordKey{cs.RecordTypeURL, cs.RecordID}
		if cur, ok := byRecord[key]; ok && cur.changeType >= cs.changeType {
			continue
		}
		byRecord[key] = cs
	}
	forwarded := make([]ChangeSet, 0, len(byRecord))
	for _, cs := range byRecord {
		forwarded = append(forwarded, cs)
	}
	return forwarded
}

func (a *changeSetApplier) forget(applied []ChangeSet) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, cs := range applied {
		a.changeSets.Delete(cs)
	}
}

func (a *changeSetApplier) computeChangeSet(ctx context.Context, changeOps recordOps, cs ChangeSet, at time.Time) {
	switch cs.RecordTypeURL {
	case idpSessionTypeURL:
		// a subsequent syncer update / reconcile should pick this case up.
		sess, ok := a.store.idpSessionLocked(cs.RecordID)
		if !ok {
			return
		}
		if cs.changeType == changeDelete {
			a.deleteIDPSessionLocked(changeOps, sess, at)
			return
		}
		a.propagateIDPSessionLocked(ctx, changeOps, sess, cs.At, at)
	case bindingTypeURL:
		ref, ok := a.store.bindingLocked(cs.RecordID)
		if !ok {
			return
		}
		switch cs.changeType {
		case changeDelete:
			a.deleteBindingLocked(changeOps, cs.RecordID, ref, at)
		case changeRevoke:
			a.revokeBindingLocked(ctx, changeOps, cs.RecordID, ref, cs.At, at)
		default:
			a.propagateBindingLocked(ctx, changeOps, cs.RecordID, ref, cs.At, at)
		}
	default:
		log.Ctx(ctx).Error().
			Str("record-type", cs.RecordTypeURL).
			Str("record-id", cs.RecordID).
			Msg("idpsession/changeset: unsupported change set record type")
	}
}

func (a *changeSetApplier) propagateIDPSessionLocked(
	ctx context.Context,
	ops recordOps,
	sess *idpsession.IDPSession,
	intentAt time.Time,
	at time.Time,
) {
	invalid := sess.GetState().GetState() == idpsession.UpstreamIdPSessionState_UPSTREAM_IDP_SESSION_STATE_INVALID
	if invalid {
		a.schedule(ctx, ChangeSet{
			At:            intentAt.Add(idpSessionGracePeriod),
			RecordID:      sess.GetId(),
			RecordTypeURL: idpSessionTypeURL,
			changeType:    changeDelete,
		})
	}

	for bindingID := range a.store.bindingsLocked(sess.GetId()) {
		ref, ok := a.store.bindingLocked(bindingID)
		if !ok {
			continue
		}
		if invalid {
			a.revokeBindingLocked(ctx, ops, bindingID, ref, intentAt, at)
			continue
		}
		a.propagateBindingLocked(ctx, ops, bindingID, ref, intentAt, at)
	}
}

func (a *changeSetApplier) propagateBindingLocked(
	ctx context.Context,
	ops recordOps,
	bindingID string,
	ref boundRef,
	intentAt time.Time,
	at time.Time,
) {
	// we can't treat an absent idpsession as proof that the session no longer
	// exists due to potential timing issues with the syncer.
	sess, ok := a.store.idpSessionLocked(ref.idpSessionID)
	if !ok {
		return
	}
	if ref.state == idpsession.BindingState_BindingState_REVOKED ||
		sess.GetState().GetState() == idpsession.UpstreamIdPSessionState_UPSTREAM_IDP_SESSION_STATE_INVALID {
		a.revokeBindingLocked(ctx, ops, bindingID, ref, intentAt, at)
		return
	}

	record, err := constructPatchedBoundRecord(ref.typeURL, bindingID, sess)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).
			Str("record-type", ref.typeURL).
			Str("record-id", bindingID).
			Msg("idpsession/changeset: cannot propagate idpsession to dependent record")
		return
	}
	ops.patch(recordKey{ref.typeURL, bindingID}, record)
}

func (a *changeSetApplier) revokeBindingLocked(
	ctx context.Context,
	ops recordOps,
	bindingID string,
	ref boundRef,
	intentAt time.Time,
	at time.Time,
) {
	// don't revoke a user binding.
	if ref.typeURL == userTypeURL {
		return
	}

	if ref.state != idpsession.BindingState_BindingState_REVOKED {
		ops.patch(recordKey{bindingTypeURL, bindingID}, databroker.NewRecord(&idpsession.Binding{
			Id:    bindingID,
			State: idpsession.BindingState_BindingState_REVOKED,
		}))
	}

	if record, err := newBoundRecord(ref.typeURL, bindingID); err == nil {
		ops.delete(recordKey{ref.typeURL, bindingID}, record, at)
	}

	a.schedule(ctx, ChangeSet{
		At:            intentAt.Add(bindingGracePeriod),
		RecordID:      bindingID,
		RecordTypeURL: bindingTypeURL,
		changeType:    changeDelete,
	})
}

func (a *changeSetApplier) deleteBindingLocked(
	ops recordOps,
	bindingID string,
	ref boundRef,
	at time.Time,
) {
	// never delete user bindings.
	if ref.typeURL == userTypeURL {
		return
	}
	if ref.state != idpsession.BindingState_BindingState_REVOKED {
		return
	}
	// keep the reference it is bound to when deleting, just in case
	ops.delete(recordKey{bindingTypeURL, bindingID}, databroker.NewRecord(&idpsession.Binding{
		Id:           bindingID,
		TypeUrl:      ref.typeURL,
		IdpSessionId: ref.idpSessionID,
		State:        ref.state,
	}), at)
}

func (a *changeSetApplier) deleteIDPSessionLocked(ops recordOps, sess *idpsession.IDPSession, at time.Time) {
	if sess.GetState().GetState() != idpsession.UpstreamIdPSessionState_UPSTREAM_IDP_SESSION_STATE_INVALID {
		return
	}
	ops.delete(recordKey{idpSessionTypeURL, sess.GetId()}, databroker.NewRecord(sess), at)
}

func (a *changeSetApplier) applyChangeSet(ctx context.Context, changeOps recordOps, at time.Time) error {
	puts := []*databroker.Record{}

	for _, diff := range changeOps {
		log.Ctx(ctx).Trace().
			Str("record-id", diff.record.Id).
			Str("type-url", diff.record.GetData().GetTypeUrl()).
			Str("reconcile-type", OpTypeStr(diff.opType)).
			Msg("submitting record operations for reconcile")
	}

	patches := map[string][]*databroker.Record{}
	for _, op := range changeOps {
		switch op.opType {
		case opDelete:
			puts = append(puts, op.record)
		case opPatch:
			patches[op.record.GetType()] = append(patches[op.record.GetType()], op.record)
		}
	}

	eg, eCtx := errgroup.WithContext(ctx)
	eg.Go(func() error {
		return databroker.PutMulti(eCtx, a.clientB.GetDataBrokerServiceClient(), puts...)
	})
	for typeURL, records := range patches {
		eg.Go(func() error {
			patched, err := a.patchMulti(eCtx, records, patchFieldMask(typeURL))
			if err != nil {
				return err
			}
			// patch returns only the records changed - a missing record indicates it was already deleted
			toRevoke := a.bindingsToRevokeFromPatched(typeURL, records, patched)

			if _, err := a.patchMulti(eCtx, toRevoke, patchFieldMask(bindingTypeURL)); err != nil {
				// on failure, reschedule the revocations.
				for _, rec := range toRevoke {
					a.schedule(ctx, ChangeSet{
						At:            at,
						RecordID:      rec.GetId(),
						RecordTypeURL: bindingTypeURL,
						changeType:    changeRevoke,
					})
				}
			}
			return nil
		})
	}
	return eg.Wait()
}

func (a *changeSetApplier) bindingsToRevokeFromPatched(
	typeURL string,
	requested []*databroker.Record,
	patched map[string]struct{},
) []*databroker.Record {
	// user records outlive their idpsession and their bindings are never revoked.
	if typeURL == userTypeURL {
		return []*databroker.Record{}
	}
	toRevoke := []*databroker.Record{}
	for _, record := range requested {
		if _, ok := patched[record.GetId()]; ok {
			continue
		}

		b := &idpsession.Binding{
			Id:    record.GetId(),
			State: idpsession.BindingState_BindingState_REVOKED,
		}
		toRevoke = append(toRevoke, databroker.NewRecord(b))
	}
	return toRevoke
}

func patchFieldMask(typeURL string) []string {
	switch typeURL {
	case sessionTypeURL:
		return []string{"id_token", "oauth_token", "claims"}
	case userTypeURL:
		return []string{"claims"}
	case mcpRefreshTokenTypeURL:
		return []string{"upstream_refresh_token"}
	case bindingTypeURL:
		return []string{"state"}
	default:
		return nil
	}
}

// patchMulti returns the ids of the records the databroker actually patched.
func (a *changeSetApplier) patchMulti(ctx context.Context, records []*databroker.Record, paths []string) (map[string]struct{}, error) {
	client := a.clientB.GetDataBrokerServiceClient()
	patched := make(map[string]struct{}, len(records))
	for _, req := range optimumPatchRequests(records, &fieldmaskpb.FieldMask{Paths: paths}) {
		res, err := client.Patch(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("patch databroker records: %w", err)
		}
		for _, record := range res.GetRecords() {
			patched[record.GetId()] = struct{}{}
		}
	}
	return patched, nil
}

func optimumPatchRequests(records []*databroker.Record, fieldMask *fieldmaskpb.FieldMask) []*databroker.PatchRequest {
	if len(records) == 0 {
		return nil
	}
	req := &databroker.PatchRequest{
		Records:   records,
		FieldMask: fieldMask,
	}
	if len(records) == 1 || proto.Size(req) <= maxPatchRequestSize {
		return []*databroker.PatchRequest{req}
	}
	return append(
		optimumPatchRequests(records[:len(records)/2], fieldMask),
		optimumPatchRequests(records[len(records)/2:], fieldMask)...,
	)
}

func constructPatchedBoundRecord(typeURL string, id string, sess *idpsession.IDPSession) (*databroker.Record, error) {
	applier := idpSessionApplier{IDPSession: sess}
	switch typeURL {
	case sessionTypeURL:
		s := &session.Session{Id: id}
		applier.ApplyToSession(s)
		return databroker.NewRecord(s), nil
	case userTypeURL:
		u := &user.User{Id: id}
		applier.ApplyToUser(u)
		return databroker.NewRecord(u), nil
	case mcpRefreshTokenTypeURL:
		token := &oauth21.MCPRefreshToken{Id: id}
		applier.ApplyToMCP(token)
		return databroker.NewRecord(token), nil
	default:
		return nil, fmt.Errorf("%s not yet supported as a binding dependency", typeURL)
	}
}

func newBoundRecord(typeURL string, id string) (*databroker.Record, error) {
	switch typeURL {
	case sessionTypeURL:
		return databroker.NewRecord(&session.Session{Id: id}), nil
	case userTypeURL:
		return databroker.NewRecord(&user.User{Id: id}), nil
	case mcpRefreshTokenTypeURL:
		return databroker.NewRecord(&oauth21.MCPRefreshToken{Id: id}), nil
	default:
		return nil, fmt.Errorf("%s not yet supported as a binding dependency", typeURL)
	}
}
