package manager

import (
	"cmp"
	"slices"

	"google.golang.org/protobuf/proto"

	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
)

// dataStore stores session and user data
type dataStore struct {
	sessions           map[string]*session.Session
	users              map[string]*user.User
	userIDToSessionIDs map[string]map[string]struct{}
}

func newDataStore() *dataStore {
	ds := new(dataStore)
	ds.deleteAllSessions()
	ds.deleteAllUsers()
	return ds
}

func (ds *dataStore) deleteAllSessions() {
	ds.sessions = make(map[string]*session.Session)
	ds.userIDToSessionIDs = make(map[string]map[string]struct{})
}

func (ds *dataStore) deleteAllUsers() {
	ds.users = make(map[string]*user.User)
}

func (ds *dataStore) deleteSession(sessionID string) {
	s := ds.sessions[sessionID]
	delete(ds.sessions, sessionID)
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

func (ds *dataStore) deleteUser(userID string) {
	delete(ds.users, userID)
}

func (ds *dataStore) getSessionAndUser(sessionID string) (s *session.Session, u *user.User) {
	s = ds.sessions[sessionID]
	if s.GetUserId() != "" {
		u = ds.users[s.GetUserId()]
	}

	// clone to avoid sharing memory
	s = clone(s)
	u = clone(u)
	return s, u
}

func (ds *dataStore) getUserAndSessions(userID string) (u *user.User, ss []*session.Session) {
	u = ds.users[userID]
	for sessionID := range ds.userIDToSessionIDs[userID] {
		ss = append(ss, ds.sessions[sessionID])
	}

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

func (ds *dataStore) putSession(s *session.Session) {
	// clone to avoid sharing memory
	s = clone(s)

	if s.GetId() != "" {
		ds.deleteSession(s.GetId())
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
}

func (ds *dataStore) putUser(u *user.User) {
	// clone to avoid sharing memory
	u = clone(u)

	if u.GetId() != "" {
		ds.users[u.GetId()] = u
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
