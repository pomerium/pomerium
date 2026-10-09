package idpsession

import (
	"context"
	"fmt"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/idpsession"
)

type synchronizedReconciler struct {
	clientB databroker.ClientGetter

	mu    sync.Mutex
	ready bool
	now   func() time.Time

	interval time.Duration
	wake     chan struct{}

	idx  IdentityIndex
	q    ChangeQueue
	idle IdleTracker
}

func newSynchronizedReconciler(
	clientB databroker.ClientGetter,
	idx IdentityIndex,
	q ChangeQueue,
	idle IdleTracker,
	interval time.Duration,
	now func() time.Time,
) *synchronizedReconciler {
	return &synchronizedReconciler{
		q:        q,
		idx:      idx,
		idle:     idle,
		interval: interval,
		wake:     make(chan struct{}, 1),
		now:      now,
		clientB:  clientB,
	}
}

func (r *synchronizedReconciler) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ready = false
}

func (r *synchronizedReconciler) Updated() {
	r.mu.Lock()
	r.ready = true
	r.mu.Unlock()
	select {
	case r.wake <- struct{}{}:
	default:
	}
}

func (r *synchronizedReconciler) Run(ctx context.Context) error {
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case <-r.wake:
		case <-ticker.C:
		}
		r.reconcile(ctx)
	}
}

func (r *synchronizedReconciler) ReconcileAtLocked(ctx context.Context, at time.Time) {
	if err := r.q.ProcessDue(at, func(cs []ChangeSet) error {
		return r.applyChangeSets(ctx, cs, at)
	}); err != nil {
		log.Ctx(ctx).Err(err).Msg("reconcile")
	}
	if err := r.deleteIdleIDPSessions(ctx, at); err != nil {
		log.Ctx(ctx).Err(err).Msg("deleting idle idp sessions")
	}
}

func (r *synchronizedReconciler) reconcile(ctx context.Context) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.ready {
		return
	}

	r.idx.Lock()
	defer r.idx.Unlock()
	// !! critical path. Prevents a wakeup trigger and a Clear trigger racing while the reconciler runs.
	r.ReconcileAtLocked(ctx, r.now())
}

func (r *synchronizedReconciler) deleteIdleIDPSessions(ctx context.Context, at time.Time) error {
	return r.idle.ProcessDue(at, func(ids []string) error {
		records := make([]*databroker.Record, 0, len(ids))
		for _, id := range ids {
			record := databroker.NewRecord(&idpsession.IDPSession{Id: id})
			record.DeletedAt = timestamppb.New(at)
			records = append(records, record)
		}
		if err := databroker.PutMulti(ctx, r.clientB.GetDataBrokerServiceClient(), records...); err != nil {
			return fmt.Errorf("delete idle idp sessions: %w", err)
		}
		return nil
	})
}

func (r *synchronizedReconciler) applyChangeSets(ctx context.Context, changes []ChangeSet, at time.Time) error {
	changeOps := recordOps{}
	revoked := map[string]struct{}{}
	for _, change := range fastForward(changes) {
		r.computeChangeSet(ctx, changeOps, revoked, change, at)
	}

	if err := r.applyRecordOps(ctx, changeOps, at); err != nil {
		return err
	}
	for bindingID := range revoked {
		r.idx.dropBindingLocked(bindingID)
	}
	return nil
}

func (r *synchronizedReconciler) computeChangeSet(
	ctx context.Context,
	changeOps recordOps,
	revoked map[string]struct{},
	change ChangeSet,
	at time.Time,
) {
	switch change.RecordTypeURL {
	case idpSessionTypeURL:
		session, ok := r.idx.idpSessionLocked(change.RecordID)
		if !ok {
			return
		}
		r.propagateIDPSession(ctx, changeOps, session)
	case bindingTypeURL:
		binding, ok := r.idx.bindingLocked(change.RecordID)
		if !ok {
			return
		}
		ref := boundRef{typeURL: binding.GetTypeUrl(), idpSessionID: binding.GetIdpSessionId()}
		if change.changeType == changeRevoke {
			r.revokeBinding(changeOps, revoked, change.RecordID, ref, at)
			return
		}
		r.propagateBinding(ctx, changeOps, change.RecordID, ref)
	default:
		log.Ctx(ctx).Error().
			Str("record-type", change.RecordTypeURL).
			Str("record-id", change.RecordID).
			Msg("idpsession/reconciler: unsupported change set record type")
	}
}

func (r *synchronizedReconciler) propagateIDPSession(
	ctx context.Context,
	changeOps recordOps,
	idpSession *idpsession.IDPSession,
) {
	for _, binding := range r.idx.bindingsByIDPSessionLocked(idpSession.GetId()) {
		ref := boundRef{typeURL: binding.GetTypeUrl(), idpSessionID: binding.GetIdpSessionId()}
		r.propagateBinding(ctx, changeOps, binding.GetId(), ref)
	}
}

func (r *synchronizedReconciler) propagateBinding(
	ctx context.Context,
	changeOps recordOps,
	bindingID string,
	ref boundRef,
) {
	idpSession, ok := r.idx.idpSessionLocked(ref.idpSessionID)
	if !ok {
		return
	}

	record, err := constructPatchedBoundRecord(ref.typeURL, bindingID, idpSession)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).
			Str("record-type", ref.typeURL).
			Str("record-id", bindingID).
			Msg("idpsession/reconciler: cannot propagate idpsession to dependent record")
		return
	}
	changeOps.patch(recordKey{ref.typeURL, bindingID}, record)
}

func (r *synchronizedReconciler) revokeBinding(
	changeOps recordOps,
	revoked map[string]struct{},
	bindingID string,
	ref boundRef,
	at time.Time,
) {
	revoked[bindingID] = struct{}{}
	if record, err := newBoundRecord(ref.typeURL, bindingID); err == nil {
		changeOps.delete(recordKey{ref.typeURL, bindingID}, record, at)
	}
	changeOps.delete(recordKey{bindingTypeURL, bindingID}, databroker.NewRecord(&idpsession.Binding{
		Id:           bindingID,
		TypeUrl:      ref.typeURL,
		IdpSessionId: ref.idpSessionID,
	}), at)
}

func (r *synchronizedReconciler) applyRecordOps(ctx context.Context, changeOps recordOps, at time.Time) error {
	puts := []*databroker.Record{}
	patches := map[string][]*databroker.Record{}
	for _, op := range changeOps {
		log.Ctx(ctx).Trace().
			Str("record-id", op.record.Id).
			Str("type-url", op.record.GetData().GetTypeUrl()).
			Str("reconcile-type", OpTypeStr(op.opType)).
			Msg("submitting record operations for reconcile")
		switch op.opType {
		case opDelete:
			puts = append(puts, op.record)
		case opPatch:
			patches[op.record.GetType()] = append(patches[op.record.GetType()], op.record)
		}
	}

	eg, eCtx := errgroup.WithContext(ctx)
	eg.Go(func() error {
		return databroker.PutMulti(eCtx, r.clientB.GetDataBrokerServiceClient(), puts...)
	})
	for typeURL, records := range patches {
		eg.Go(func() error {
			patched, err := r.patchMulti(eCtx, records, patchFieldMask(typeURL))
			if err != nil {
				return err
			}
			toDelete := bindingsToDeleteFromPatched(typeURL, records, patched, at)
			return databroker.PutMulti(eCtx, r.clientB.GetDataBrokerServiceClient(), toDelete...)
		})
	}
	return eg.Wait()
}

func bindingsToDeleteFromPatched(
	typeURL string,
	requested []*databroker.Record,
	patched map[string]struct{},
	at time.Time,
) []*databroker.Record {
	if typeURL == idpSessionTypeURL {
		return nil
	}
	toDelete := []*databroker.Record{}
	for _, record := range requested {
		if _, ok := patched[record.GetId()]; ok {
			continue
		}
		record := databroker.NewRecord(&idpsession.Binding{
			Id:      record.GetId(),
			TypeUrl: typeURL,
		})
		record.DeletedAt = timestamppb.New(at)
		toDelete = append(toDelete, record)
	}
	return toDelete
}

func (r *synchronizedReconciler) patchMulti(
	ctx context.Context,
	records []*databroker.Record,
	paths []string,
) (map[string]struct{}, error) {
	client := r.clientB.GetDataBrokerServiceClient()
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

type SyncNotifier interface {
	Reset()
	Updated()
}

var _ SyncNotifier = (*synchronizedReconciler)(nil)
