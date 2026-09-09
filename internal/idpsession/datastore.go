package idpsession

import (
	"context"
	"fmt"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	oauth21 "github.com/pomerium/pomerium/internal/oauth21/gen"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/idpsession"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
)

type dataStore struct {
	*sync.Mutex
	idpSessions   map[string]*idpsession.IDPSession
	idpToBindings map[string]map[string]*idpsession.Binding
	recordSet     databroker.RecordSetBundle

	bindingGracePeriod    time.Duration
	idpSessionGracePeriod time.Duration
	now                   func() time.Time
}

func newDataStore(now func() time.Time) *dataStore {
	return &dataStore{
		idpSessions:   map[string]*idpsession.IDPSession{},
		idpToBindings: make(map[string]map[string]*idpsession.Binding),
		recordSet:     make(databroker.RecordSetBundle),
		Mutex:         &sync.Mutex{},

		bindingGracePeriod:    time.Hour,
		idpSessionGracePeriod: time.Hour,
		now:                   now,
	}
}

func (ds *dataStore) reset() {
	ds.Lock()
	defer ds.Unlock()
	ds.idpSessions = map[string]*idpsession.IDPSession{}
	ds.idpToBindings = map[string]map[string]*idpsession.Binding{}
	ds.recordSet = make(databroker.RecordSetBundle)
}

func (ds *dataStore) deleteIDPSession(id string) {
	ds.Lock()
	defer ds.Unlock()
	delete(ds.idpSessions, id)
}

func (ds *dataStore) putIDPSession(is *idpsession.IDPSession) {
	ds.Lock()
	defer ds.Unlock()
	ds.idpSessions[is.Id] = is
}

func (ds *dataStore) getIDPSession(id string) (s *idpsession.IDPSession) {
	ds.Lock()
	defer ds.Unlock()
	s = ds.idpSessions[id]

	if s == nil {
		return nil
	}
	return proto.CloneOf(s)
}

// IDP session bindings

func (ds *dataStore) updateMapping(b *idpsession.Binding) {
	ds.Lock()
	defer ds.Unlock()
	idpSessID := b.GetIdpSessionId()
	_, ok := ds.idpToBindings[idpSessID]
	if !ok {
		ds.idpToBindings[idpSessID] = make(map[string]*idpsession.Binding)
	}
	ds.idpToBindings[idpSessID][b.GetId()] = b
}

func (ds *dataStore) deleteMapping(b *idpsession.Binding) {
	ds.Lock()
	defer ds.Unlock()

	idpSessID := b.GetIdpSessionId()
	_, ok := ds.idpToBindings[idpSessID]
	if !ok {
		return
	}
	delete(ds.idpToBindings[idpSessID], b.GetId())
}

// generic records that are being watched.

func (ds *dataStore) addRecord(rec *databroker.Record) {
	ds.Lock()
	defer ds.Unlock()
	ds.recordSet.Add(rec)
}

func (ds *dataStore) deleteRecord(rec *databroker.Record) {
	ds.Lock()
	defer ds.Unlock()

	recordSet, ok := ds.recordSet[rec.Data.GetTypeUrl()]
	if !ok {
		return
	}
	delete(recordSet, rec.GetId())
}

// reconciler helpers

func (ds *dataStore) getCurrentChangesetLocked(_ context.Context) (databroker.RecordSetBundle, error) {
	current := make(databroker.RecordSetBundle)

	// Users are never deleted by the identity manager.
	if users, ok := ds.recordSet["type.googleapis.com/user.User"]; ok {
		for _, record := range users {
			current.Add(record)
		}
	}

	// in this model bindings are the authoritative source for mapping idpsession -> dependent updates.
	for _, bindings := range ds.idpToBindings {
		for _, binding := range bindings {
			current.Add(databroker.NewRecord(binding))
			if record, ok := ds.recordSet.Get(binding.GetTypeUrl(), binding.GetId()); ok {
				current.Add(record)
			}
		}
	}
	for _, idpSess := range ds.idpSessions {
		current.Add(databroker.NewRecord(idpSess))
	}

	return current, nil
}

func (ds *dataStore) targetChangeSetLocked(_ context.Context) (databroker.RecordSetBundle, error) {
	target := make(databroker.RecordSetBundle)
	now := ds.now()
	// never delete user.User. Add them here first so changes get applied
	if userSet, ok := ds.recordSet["type.googleapis.com/user.User"]; ok {
		for _, user := range userSet {
			target.Add(user)
		}
	}

	// idpsession exists until its grace period.
	for _, idpSess := range ds.idpSessions {
		if invalidatedAt := idpSess.GetState().GetInvalidatedAt(); invalidatedAt != nil &&
			now.After(invalidatedAt.AsTime().Add(ds.idpSessionGracePeriod)) {
			continue
		}
		target.Add(databroker.NewRecord(idpSess))
	}

	for idpSessionID, bindings := range ds.idpToBindings {
		idpSess := ds.idpSessions[idpSessionID]
		for _, binding := range bindings {
			// an invalid idpsession revokes its bindings.
			if idpSess.GetState().GetState() == idpsession.UpstreamIdPSessionState_UPSTREAM_IDP_SESSION_STATE_INVALID {
				binding = binding.Revoke()
			}
			if revokedAt := binding.GetRevokedAt(); revokedAt != nil && now.After(revokedAt.AsTime().Add(ds.bindingGracePeriod)) {
				// delete the binding
				continue
			}
			target.Add(databroker.NewRecord(binding))
			if binding.GetState() == idpsession.BindingState_BindingState_REVOKED {
				// don't add depedent records to the target set
				continue
			}

			got, ok := ds.recordSet.Get(binding.TypeUrl, binding.Id)
			if !ok {
				// a subsequent reconcile will pick this case up, in the case that the binding and depedent record
				// update weren't observed in the same notify update
				continue
			}
			// we can't treat an absent record as proof that the session no longer exists due to timing issues with the syncer.
			if idpSess == nil {
				target.Add(got)
				continue
			}
			ds.addDependentRecords(target, got, idpSess)
		}
	}
	return target, nil
}

func (ds *dataStore) addDependentRecords(
	target databroker.RecordSetBundle,
	record *databroker.Record,
	idpSess *idpsession.IDPSession,
) {
	applier := idpSessionApplier{IDPSession: idpSess}
	rec := proto.CloneOf(record)

	switch typeURL := rec.GetData().TypeUrl; typeURL {
	case "type.googleapis.com/session.Session":
		sess := &session.Session{}
		if err := rec.GetData().UnmarshalTo(sess); err != nil {
			panic(err)
		}
		applier.ApplyToSession(sess)
		target.Add(databroker.NewRecord(sess))
	case "type.googleapis.com/user.User":
		user := &user.User{}
		if err := rec.GetData().UnmarshalTo(user); err != nil {
			panic(err)
		}
		applier.ApplyToUser(user)
		target.Add(databroker.NewRecord(user))
	case "type.googleapis.com/oauth21.MCPRefreshToken":
		mcp := &oauth21.MCPRefreshToken{}
		if err := rec.GetData().UnmarshalTo(mcp); err != nil {
			panic(err)
		}
		applier.ApplyToMCP(mcp)
		target.Add(databroker.NewRecord(mcp))
	default:
		panic(fmt.Sprintf("%s not yet supported as a binding dependency", typeURL))
	}
}
