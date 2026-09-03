package idpsession

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"sync"

	oauth21 "github.com/pomerium/pomerium/internal/oauth21/gen"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/idpsession"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"google.golang.org/protobuf/proto"
)

type dataStore struct {
	*sync.Mutex
	idpSessions   map[string]*idpsession.IDPSession
	idpToBindings map[string]map[string]*idpsession.IDPSessionBinding
	recordSet     databroker.RecordSetBundle
}

func newDataStore() *dataStore {
	return &dataStore{
		idpSessions:   map[string]*idpsession.IDPSession{},
		idpToBindings: make(map[string]map[string]*idpsession.IDPSessionBinding),
		recordSet:     make(databroker.RecordSetBundle),
		Mutex:         &sync.Mutex{},
	}
}

// idpSessions

func (ds *dataStore) deleteAllIDPSessions() {
	ds.Lock()
	defer ds.Unlock()
	ds.idpSessions = make(map[string]*idpsession.IDPSession)
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

func (ds *dataStore) updateMapping(b *idpsession.IDPSessionBinding) {
	ds.Lock()
	defer ds.Unlock()
	idpSessID := b.GetIdpSessionId()
	_, ok := ds.idpToBindings[idpSessID]
	if !ok {
		ds.idpToBindings[idpSessID] = make(map[string]*idpsession.IDPSessionBinding)
	}
	ds.idpToBindings[idpSessID][b.GetId()] = b
}

func (ds *dataStore) deleteMapping(b *idpsession.IDPSessionBinding) {
	ds.Lock()
	defer ds.Unlock()

	idpSessID := b.GetIdpSessionId()
	_, ok := ds.idpToBindings[idpSessID]
	if !ok {
		return
	}
	delete(ds.idpToBindings[idpSessID], b.GetId())
}

func (ds *dataStore) deleteAllMappings() {
	ds.Lock()
	defer ds.Unlock()
	ds.idpToBindings = map[string]map[string]*idpsession.IDPSessionBinding{}
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

func (ds *dataStore) deleteRecordType(typeURL string) {
	ds.Lock()
	defer ds.Unlock()
	delete(ds.recordSet, typeURL)
}

// reconciler helpers

func (ds *dataStore) getCurrentChangesetLocked(_ context.Context) (databroker.RecordSetBundle, error) {
	return ds.recordSet, nil
}

func (ds *dataStore) lookupBindingsLocked(isID string) []*idpsession.IDPSessionBinding {
	return slices.Collect(maps.Values(ds.idpToBindings[isID]))
}

func (ds *dataStore) targetChangeSetLocked(_ context.Context) (databroker.RecordSetBundle, error) {
	newRecordSet := make(databroker.RecordSetBundle)
	for _, idpSess := range ds.idpSessions {
		retBindings := ds.lookupBindingsLocked(idpSess.Id)
		for _, binding := range retBindings {
			got, ok := ds.recordSet.Get(binding.TypeUrl, binding.Id)
			if !ok {
				// fine to skip, a subsequent reconcile will pick this case up
				continue
			}
			applier := idpSessionApplier{IDPSession: idpSess}
			rec := proto.CloneOf(got)

			switch typeURL := rec.GetData().TypeUrl; typeURL {
			case "type.googleapis.com/session.Session":
				sess := &session.Session{}
				if err := rec.GetData().UnmarshalTo(sess); err != nil {
					panic(err)
				}
				applier.ApplyToSession(sess)
				newRecordSet.Add(databroker.NewRecord(sess))
			case "type.googleapis.com/user.User":
				user := &user.User{}
				if err := rec.GetData().UnmarshalTo(user); err != nil {
					panic(err)
				}
				applier.ApplyToUser(user)
				newRecordSet.Add(databroker.NewRecord(user))
			case "type.googleapis.com/oauth21.MCPRefreshToken":
				mcp := &oauth21.MCPRefreshToken{}
				if err := rec.GetData().UnmarshalTo(mcp); err != nil {
					panic(err)
				}
				applier.ApplyToMCP(mcp)
				newRecordSet.Add(databroker.NewRecord(mcp))
			default:
				panic(fmt.Sprintf("%s not yet supported as a binding dependency", typeURL))
			}
		}
	}
	return newRecordSet, nil
}
