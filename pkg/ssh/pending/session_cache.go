package pending

import (
	"log/slog"
	"sync"
	"time"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func isValid(req CodeRequest) bool {
	now := time.Now()
	if req.DeletedAt != nil {
		return false
	}
	if req.Req.ExpiresAt.AsTime().Before(now) {
		return false
	}
	return true
}

type CodeRequest struct {
	Code      CodeID
	DeletedAt *timestamppb.Timestamp
	Req       *session.SessionBindingRequest
}

type sessionCache struct {
	codesMu *sync.RWMutex
	codes   map[SessionID][]CodeRequest

	sessionsMu *sync.RWMutex
	sessions   map[SessionID][]*databroker.Record
}

func NewSessionCache() *sessionCache {
	return &sessionCache{
		codesMu:    &sync.RWMutex{},
		sessionsMu: &sync.RWMutex{},
		codes:      map[SessionID][]CodeRequest{},
		sessions:   map[SessionID][]*databroker.Record{},
	}
}

func (s *sessionCache) IsCodeValid(sessionID SessionID, codeId CodeID) bool {
	s.codesMu.RLock()
	defer s.codesMu.RUnlock()
	vals, ok := s.codes[sessionID]
	if !ok {
		return ok
	}
	for _, v := range vals {
		if v.Code == codeId {
			return isValid(v)
		}
	}
	return false
}

func (s *sessionCache) GetCode(sessionID SessionID) (CodeID, bool) {
	s.codesMu.RLock()
	defer s.codesMu.RUnlock()

	val, ok := s.codes[sessionID]
	if !ok {
		return "", ok
	}

	for _, r := range val {
		if isValid(r) {
			return r.Code, true
		}
	}
	return "", false
}

func (s *sessionCache) PutCode(sessionID SessionID, req CodeRequest) {
	s.codesMu.Lock()
	defer s.codesMu.Unlock()
	slog.Default().With("sessionID", sessionID).With("codeID", req.Code).Info("storing code in cache")

	_, ok := s.codes[sessionID]
	if !ok {
		s.codes[sessionID] = []CodeRequest{}
	}
	idx := -1
	for i, codeReq := range s.codes[sessionID] {
		if codeReq.Code == req.Code {
			// existing code
			idx = i
			break
		}
	}

	if idx >= 0 {
		s.codes[sessionID][idx] = req
	} else {
		s.codes[sessionID] = append(s.codes[sessionID], req)
	}

}

func (s *sessionCache) PutSession(sessionID SessionID, recs []*databroker.Record) {
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	slog.Default().With("sessionID", sessionID).Info("putting session")
	s.sessions[sessionID] = recs
}

func (s *sessionCache) GetSession(sessionID SessionID) ([]*databroker.Record, bool) {
	s.sessionsMu.RLock()
	defer s.sessionsMu.RUnlock()
	val, ok := s.sessions[sessionID]
	return val, ok
}
