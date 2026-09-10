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
	"github.com/pomerium/pomerium/pkg/slices"
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

const (
	// changePropagate copies idpsession state onto the dependent records bound to it
	changePropagate ChangeSetType = 1
	// changeRevoke marks bindings revoked and deletes their dependent records
	changeRevoke ChangeSetType = 2
	// changeDelete removes a record once its revocation grace period has elapsed
	changeDelete ChangeSetType = 3
)

type boundRef struct {
	typeURL string
	state   idpsession.BindingState
}

// A changeSetStore keeps track of idpsession.IDPSession and the records they are bound to through
// idpsession.Binding
type changeSetStore struct {
	*sync.Mutex

	idpSessions map[string]*idpsession.IDPSession
	// idpsession id -> binding id -> binding
	bindings map[string]map[string]boundRef
}

func newChangeSetStore() *changeSetStore {
	return &changeSetStore{
		Mutex:       &sync.Mutex{},
		idpSessions: map[string]*idpsession.IDPSession{},
		bindings:    map[string]map[string]boundRef{},
	}
}

func (s *changeSetStore) reset() {
	s.Lock()
	defer s.Unlock()
	s.idpSessions = map[string]*idpsession.IDPSession{}
	s.bindings = map[string]map[string]boundRef{}
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
		s.bindings[idpSessionID] = map[string]boundRef{}
	}
	s.bindings[idpSessionID][binding.GetId()] = boundRef{
		typeURL: binding.GetTypeUrl(),
		state:   binding.GetState(),
	}
}

func (s *changeSetStore) deleteBinding(binding *idpsession.Binding) {
	s.Lock()
	defer s.Unlock()
	idpSessionID := binding.GetIdpSessionId()
	delete(s.bindings[idpSessionID], binding.GetId())
	if len(s.bindings[idpSessionID]) == 0 {
		delete(s.bindings, idpSessionID)
	}
}

func (s *changeSetStore) idpSessionLocked(id string) (*idpsession.IDPSession, bool) {
	sess, ok := s.idpSessions[id]
	return sess, ok
}

func (s *changeSetStore) bindingLocked(idpSessionID string, bindingID string) (boundRef, bool) {
	ref, ok := s.bindings[idpSessionID][bindingID]
	return ref, ok
}

func (s *changeSetStore) bindingsLocked(idpSessionID string) map[string]boundRef {
	return s.bindings[idpSessionID]
}

type ChangeSet struct {
	At            time.Time
	RecordID      string
	RecordTypeURL string
	// IDPSessionID is set for idpsession.Binding changes
	IDPSessionID string
	changeType   ChangeSetType
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

type recordKey = [2]string

type recordOp struct {
	opType opType
	record *databroker.Record
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

func (a *changeSetApplier) onUpdateIDPSession(sess *idpsession.IDPSession, at time.Time) {
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
	a.schedule(cs)
}

func (a *changeSetApplier) onUpdateBinding(binding *idpsession.Binding, at time.Time) {
	cs := ChangeSet{
		At:            at,
		RecordID:      binding.GetId(),
		RecordTypeURL: bindingTypeURL,
		IDPSessionID:  binding.GetIdpSessionId(),
		changeType:    changePropagate,
	}
	if binding.GetState() == idpsession.BindingState_BindingState_REVOKED {
		cs.changeType = changeRevoke
	}
	a.store.putBinding(binding)
	a.schedule(cs)
}

func (a *changeSetApplier) schedule(cs ChangeSet) {
	a.mu.Lock()
	defer a.mu.Unlock()
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

	changeOps := map[recordKey]recordOp{}
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

type changeSetKey struct {
	recordTypeURL string
	recordID      string
	changeType    ChangeSetType
}

func fastForward(change []ChangeSet) []ChangeSet {
	return slices.UniqueBy(change, func(cs ChangeSet) changeSetKey {
		return changeSetKey{
			recordTypeURL: cs.RecordTypeURL,
			recordID:      cs.RecordID,
			changeType:    cs.changeType,
		}
	})
}

func (a *changeSetApplier) forget(applied []ChangeSet) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, cs := range applied {
		a.changeSets.Delete(cs)
	}
}

func (a *changeSetApplier) computeChangeSet(ctx context.Context, changeOps map[recordKey]recordOp, cs ChangeSet, at time.Time) {
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
		a.propagateIDPSessionLocked(ctx, changeOps, sess, at)
	case bindingTypeURL:
		ref, ok := a.store.bindingLocked(cs.IDPSessionID, cs.RecordID)
		if !ok {
			return
		}
		if cs.changeType == changeDelete {
			a.deleteBindingLocked(changeOps, cs.IDPSessionID, cs.RecordID, ref, at)
			return
		}
		a.propagateBindingLocked(ctx, changeOps, cs.IDPSessionID, cs.RecordID, ref, at)
	default:
		log.Ctx(ctx).Error().
			Str("record-type", cs.RecordTypeURL).
			Str("record-id", cs.RecordID).
			Msg("idpsession/changeset: unsupported change set record type")
	}
}

func (a *changeSetApplier) propagateIDPSessionLocked(
	ctx context.Context,
	ops map[recordKey]recordOp,
	sess *idpsession.IDPSession,
	at time.Time,
) {
	invalid := sess.GetState().GetState() == idpsession.UpstreamIdPSessionState_UPSTREAM_IDP_SESSION_STATE_INVALID
	if invalid {
		a.schedule(ChangeSet{
			At:            at.Add(idpSessionGracePeriod),
			RecordID:      sess.GetId(),
			RecordTypeURL: idpSessionTypeURL,
			changeType:    changeDelete,
		})
	}

	for bindingID, ref := range a.store.bindingsLocked(sess.GetId()) {
		if invalid {
			a.revokeBindingLocked(ops, sess.GetId(), bindingID, ref, at)
			continue
		}
		a.propagateBindingLocked(ctx, ops, sess.GetId(), bindingID, ref, at)
	}
}

func (a *changeSetApplier) propagateBindingLocked(
	ctx context.Context,
	ops map[recordKey]recordOp,
	idpSessionID string,
	bindingID string,
	ref boundRef,
	at time.Time,
) {
	// we can't treat an absent idpsession as proof that the session no longer
	// exists due to potential timing issues with the syncer.
	sess, ok := a.store.idpSessionLocked(idpSessionID)
	if !ok {
		return
	}
	if ref.state == idpsession.BindingState_BindingState_REVOKED ||
		sess.GetState().GetState() == idpsession.UpstreamIdPSessionState_UPSTREAM_IDP_SESSION_STATE_INVALID {
		a.revokeBindingLocked(ops, idpSessionID, bindingID, ref, at)
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
	ops[recordKey{ref.typeURL, bindingID}] = recordOp{
		opType: opPatch,
		record: record,
	}
}

func (a *changeSetApplier) revokeBindingLocked(
	ops map[recordKey]recordOp,
	idpSessionID string,
	bindingID string,
	ref boundRef,
	at time.Time,
) {
	// don't revoke a user binding.
	if ref.typeURL == userTypeURL {
		return
	}

	if ref.state != idpsession.BindingState_BindingState_REVOKED {
		ops[recordKey{bindingTypeURL, bindingID}] = recordOp{
			opType: opPatch,
			record: databroker.NewRecord(&idpsession.Binding{
				Id:    bindingID,
				State: idpsession.BindingState_BindingState_REVOKED,
			}),
		}
	}

	if record, err := newBoundRecord(ref.typeURL, bindingID); err == nil {
		ops[recordKey{ref.typeURL, bindingID}] = deleteOp(record, at)
	}

	a.schedule(ChangeSet{
		At:            at.Add(bindingGracePeriod),
		RecordID:      bindingID,
		RecordTypeURL: bindingTypeURL,
		IDPSessionID:  idpSessionID,
		changeType:    changeDelete,
	})
}

func (a *changeSetApplier) deleteBindingLocked(
	ops map[recordKey]recordOp,
	idpSessionID string,
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
	ops[recordKey{bindingTypeURL, bindingID}] = deleteOp(databroker.NewRecord(&idpsession.Binding{
		Id:           bindingID,
		TypeUrl:      ref.typeURL,
		IdpSessionId: idpSessionID,
		State:        ref.state,
	}), at)
}

func (a *changeSetApplier) deleteIDPSessionLocked(ops map[recordKey]recordOp, sess *idpsession.IDPSession, at time.Time) {
	if sess.GetState().GetState() != idpsession.UpstreamIdPSessionState_UPSTREAM_IDP_SESSION_STATE_INVALID {
		return
	}
	ops[recordKey{idpSessionTypeURL, sess.GetId()}] = deleteOp(databroker.NewRecord(sess), at)
}

func (a *changeSetApplier) applyChangeSet(ctx context.Context, changeOps map[recordKey]recordOp, at time.Time) error {
	puts := []*databroker.Record{}
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
			// patch returns only the records changed - a missing record indicates it was already deleted
			patched, err := a.patchMulti(eCtx, records, patchFieldMask(typeURL))
			if err != nil {
				return err
			}
			a.scheduleMissingRecordRevocation(typeURL, records, patched, at)
			return nil
		})
	}
	return eg.Wait()
}

func (a *changeSetApplier) scheduleMissingRecordRevocation(
	typeURL string,
	requested []*databroker.Record,
	patched map[string]struct{},
	at time.Time,
) {
	// user records outlive their idpsession and their bindings are never revoked.
	if typeURL == userTypeURL {
		return
	}
	for _, record := range requested {
		if _, ok := patched[record.GetId()]; ok {
			continue
		}

		a.schedule(ChangeSet{
			At:            at,
			RecordID:      record.GetId(),
			RecordTypeURL: bindingTypeURL,
			changeType:    changeRevoke,
		})
	}
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

func deleteOp(record *databroker.Record, at time.Time) recordOp {
	record.DeletedAt = timestamppb.New(at)
	return recordOp{
		opType: opDelete,
		record: record,
	}
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
