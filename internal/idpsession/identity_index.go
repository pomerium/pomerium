package idpsession

import (
	"context"
	"maps"
	"slices"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/pomerium/pomerium/pkg/grpc/idpsession"
	"github.com/pomerium/pomerium/pkg/grpc/user"
)

const idpSessionIdleWindow = time.Hour

type identityIndex struct {
	queue ChangeQueue
	idle  IdleTracker

	mu sync.RWMutex

	idpSessions          map[string]*idpsession.IDPSession
	idpSessionsBySID     map[string]map[string]struct{}
	idpSessionsByUser    map[string]map[string]struct{}
	bindingRefs          map[string]boundRef
	bindingsByIDPSession map[string]map[string]struct{}
	users                map[string]*user.User
}

func NewIdentityIndex(queue ChangeQueue, idle IdleTracker) IdentityIndex {
	s := &identityIndex{queue: queue, idle: idle}
	s.clearLocked()
	return s
}

func (s *identityIndex) GetUser(id string) *user.User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[id]
	if !ok {
		return nil
	}
	return proto.CloneOf(u)
}

func (s *identityIndex) PutUser(u *user.User) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[u.GetId()] = u
}

func (s *identityIndex) DeleteUser(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.users, id)
}

func (s *identityIndex) Lock() {
	s.mu.Lock()
}

func (s *identityIndex) Unlock() {
	s.mu.Unlock()
}

func (s *identityIndex) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.clearLocked()
	s.queue.Reset()
	s.idle.Reset()
}

func (s *identityIndex) IDPSession(id string) (*idpsession.IDPSession, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	session, ok := s.idpSessions[id]
	if !ok {
		return nil, false
	}
	return proto.CloneOf(session), true
}

func (s *identityIndex) IDPSessionsBySID(sid string) []*idpsession.IDPSession {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sessionsForLocked(s.idpSessionsBySID, sid)
}

func (s *identityIndex) IDPSessionsByUser(userID string) []*idpsession.IDPSession {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sessionsForLocked(s.idpSessionsByUser, userID)
}

func (s *identityIndex) idpSessionLocked(id string) (*idpsession.IDPSession, bool) {
	session, ok := s.idpSessions[id]
	return proto.CloneOf(session), ok
}

func (s *identityIndex) bindingLocked(id string) (*idpsession.Binding, bool) {
	ref, ok := s.bindingRefs[id]
	if !ok {
		return nil, false
	}
	return &idpsession.Binding{Id: id, TypeUrl: ref.typeURL, IdpSessionId: ref.idpSessionID}, true
}

func (s *identityIndex) bindingsByIDPSessionLocked(id string) []*idpsession.Binding {
	ids := slices.Sorted(maps.Keys(s.bindingsByIDPSession[id]))
	bindings := make([]*idpsession.Binding, 0, len(ids))
	for _, bindingID := range ids {
		ref := s.bindingRefs[bindingID]
		bindings = append(bindings, &idpsession.Binding{
			Id: bindingID, TypeUrl: ref.typeURL, IdpSessionId: ref.idpSessionID,
		})
	}
	return bindings
}

func (s *identityIndex) dropBindingLocked(id string) {
	delete(s.bindingRefs, id)
}

func (s *identityIndex) PutIDPSession(session *idpsession.IDPSession, at time.Time) {
	id := session.GetId()
	s.mu.Lock()
	defer s.mu.Unlock()
	if previous, ok := s.idpSessions[id]; ok {
		if previous.GetSid() != "" {
			removeIndexEntry(s.idpSessionsBySID, previous.GetSid(), id)
		}
		removeIndexEntry(s.idpSessionsByUser, previous.GetUserId(), id)
	}
	s.idpSessions[id] = proto.CloneOf(session)
	if session.GetSid() != "" {
		addIndexEntry(s.idpSessionsBySID, session.GetSid(), id)
	}
	addIndexEntry(s.idpSessionsByUser, session.GetUserId(), id)
	idle := len(s.bindingsByIDPSession[id]) == 0

	if idle {
		s.idle.Set(id, at.Add(idpSessionIdleWindow))
	} else {
		s.idle.Clear(id)
	}
	s.scheduleLocked(ChangeSet{At: at, RecordID: id, RecordTypeURL: idpSessionTypeURL, changeType: changePropagate})
}

func (s *identityIndex) DeleteIDPSession(id string, at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if session, ok := s.idpSessions[id]; ok {
		if session.GetSid() != "" {
			removeIndexEntry(s.idpSessionsBySID, session.GetSid(), id)
		}
		removeIndexEntry(s.idpSessionsByUser, session.GetUserId(), id)
	}
	delete(s.idpSessions, id)
	bindingIDs := slices.Sorted(maps.Keys(s.bindingsByIDPSession[id]))
	delete(s.bindingsByIDPSession, id)

	s.idle.Clear(id)
	for _, bindingID := range bindingIDs {
		s.scheduleRevokeLocked(bindingID, at)
	}
}

func (s *identityIndex) PutBinding(binding *idpsession.Binding, at time.Time) {
	id := binding.GetId()
	parentID := binding.GetIdpSessionId()
	s.mu.Lock()
	defer s.mu.Unlock()

	s.bindingRefs[id] = boundRef{typeURL: binding.GetTypeUrl(), idpSessionID: parentID}
	addIndexEntry(s.bindingsByIDPSession, parentID, id)
	s.idle.Clear(parentID)
	s.scheduleLocked(ChangeSet{At: at, RecordID: id, RecordTypeURL: bindingTypeURL, changeType: changePropagate})
}

func (s *identityIndex) DeleteBinding(id string, at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ref, ok := s.bindingRefs[id]
	if ok {
		removeIndexEntry(s.bindingsByIDPSession, ref.idpSessionID, id)
	}
	_, parentExists := s.idpSessions[ref.idpSessionID]
	parentIdle := parentExists && len(s.bindingsByIDPSession[ref.idpSessionID]) == 0

	if !ok {
		return
	}
	if parentIdle {
		s.idle.Set(ref.idpSessionID, at.Add(idpSessionIdleWindow))
	}
	s.scheduleRevokeLocked(id, at)
}

func (s *identityIndex) sessionsForLocked(index map[string]map[string]struct{}, key string) []*idpsession.IDPSession {
	ids := slices.Sorted(maps.Keys(index[key]))
	result := make([]*idpsession.IDPSession, 0, len(ids))
	for _, id := range ids {
		if session, ok := s.idpSessions[id]; ok {
			result = append(result, proto.CloneOf(session))
		}
	}
	return result
}

func (s *identityIndex) scheduleRevokeLocked(bindingID string, at time.Time) {
	s.scheduleLocked(ChangeSet{At: at, RecordID: bindingID, RecordTypeURL: bindingTypeURL, changeType: changeRevoke})
}

func (s *identityIndex) scheduleLocked(change ChangeSet) {
	s.queue.Schedule(context.Background(), change)
}

func (s *identityIndex) clearLocked() {
	s.idpSessions = make(map[string]*idpsession.IDPSession)
	s.idpSessionsBySID = make(map[string]map[string]struct{})
	s.idpSessionsByUser = make(map[string]map[string]struct{})
	s.bindingRefs = make(map[string]boundRef)
	s.bindingsByIDPSession = make(map[string]map[string]struct{})
	s.users = make(map[string]*user.User)
}

func addIndexEntry(index map[string]map[string]struct{}, key, id string) {
	if key == "" {
		panic("bug: invalid key")
	}
	if index[key] == nil {
		index[key] = make(map[string]struct{})
	}
	index[key][id] = struct{}{}
}

func removeIndexEntry(index map[string]map[string]struct{}, key, id string) {
	if key == "" {
		panic("bug: invalid key")
	}
	delete(index[key], id)
	if len(index[key]) == 0 {
		delete(index, key)
	}
}

var _ IdentityIndex = (*identityIndex)(nil)
