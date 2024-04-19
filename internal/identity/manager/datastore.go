package manager

import (
	"cmp"
	"slices"
	"sync"

	"google.golang.org/protobuf/proto"

	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
)

// dataStore stores session and user data. All public methods are thread-safe.
type dataStore struct {
	mu                 sync.Mutex
	sessions           map[string]*session.Session
	users              map[string]*user.User
	userIDToSessionIDs map[string]map[string]struct{}
}

func newDataStore() *dataStore {
	return &dataStore{
		sessions:           make(map[string]*session.Session),
		users:              make(map[string]*user.User),
		userIDToSessionIDs: make(map[string]map[string]struct{}),
	}
}

// DeleteSession deletes a session.
func (ds *dataStore) DeleteSession(sID string) {
	ds.mu.Lock()
	ds.deleteSessionLocked(sID)
	ds.mu.Unlock()
}

// DeleteUser deletes a user.
func (ds *dataStore) DeleteUser(userID string) {
	ds.mu.Lock()
	delete(ds.users, userID)
	ds.mu.Unlock()
}

// GetSessionAndUser gets a session and its associated user.
func (ds *dataStore) GetSessionAndUser(sessionID string) (s *session.Session, u *user.User) {
	ds.mu.Lock()
	s = ds.sessions[sessionID]
	if s.GetUserId() != "" {
		u = ds.users[s.GetUserId()]
	}
	ds.mu.Unlock()

	// clone to avoid sharing memory
	s = clone(s)
	u = clone(u)
	return s, u
}

// GetUserAndSessions gets a user and all of its associated sessions.
func (ds *dataStore) GetUserAndSessions(userID string) (u *user.User, ss []*session.Session) {
	ds.mu.Lock()
	u = ds.users[userID]
	for sessionID := range ds.userIDToSessionIDs[userID] {
		ss = append(ss, ds.sessions[sessionID])
	}
	ds.mu.Unlock()

	// remove nils and sort by id
	ss = slices.Compact(ss)
	slices.SortFunc(ss, func(a, b *session.Session) int {
		return cmp.Compare(a.GetId(), b.GetId())
	})

	// clone to avoid sharing memory
	u = clone(u)
	for i := range ss {
		ss[i] = clone(ss[i])
	}
	return u, ss
}

// PutSession stores the session.
func (ds *dataStore) PutSession(s *session.Session) {
	// clone to avoid sharing memory
	s = clone(s)

	ds.mu.Lock()
	if s.GetId() != "" {
		ds.deleteSessionLocked(s.GetId())
		ds.sessions[s.GetId()] = s
		if s.GetUserId() != "" {
			m, ok := ds.userIDToSessionIDs[s.GetUserId()]
			if !ok {
				m = make(map[string]struct{})
				ds.userIDToSessionIDs[s.GetUserId()] = m
			}
			m[s.GetId()] = struct{}{}
		}
	}
	ds.mu.Unlock()
}

// PutUser stores the user.
func (ds *dataStore) PutUser(u *user.User) {
	// clone to avoid sharing memory
	u = clone(u)

	ds.mu.Lock()
	if u.GetId() != "" {
		ds.users[u.GetId()] = u
	}
	ds.mu.Unlock()
}

func (ds *dataStore) deleteSessionLocked(sID string) {
	s := ds.sessions[sID]
	delete(ds.sessions, sID)
	if s.GetUserId() == "" {
		return
	}

	m := ds.userIDToSessionIDs[s.GetUserId()]
	if m != nil {
		delete(m, s.GetId())
	}
	if len(m) == 0 {
		delete(ds.userIDToSessionIDs, s.GetUserId())
	}
}

// clone clones a protobuf message
func clone[T any, U interface {
	*T
	proto.Message
}](src U) U {
	if src == nil {
		return src
	}
	return proto.Clone(src).(U)
}
