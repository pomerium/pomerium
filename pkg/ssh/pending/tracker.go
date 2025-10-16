package pending

import (
	"sync"
	"time"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type Tracker interface {
	Inc(sessionID string)
	Dec(sessionID string)
	GetRecords(sessionID string) (<-chan []*databroker.Record, bool)
	GetBindingRequest(sessionID string) (<-chan *SessionBindingCode, bool)
}

type SessionBindingCode struct {
	Code      string
	DeletedAt *timestamppb.Timestamp
	Req       *session.SessionBindingRequest
}

func (s *SessionBindingCode) IsValid() bool {
	if s.DeletedAt != nil {
		return false
	}
	if s.Req.ExpiresAt.AsTime().Before(time.Now()) {
		return false
	}
	return true
}

type pendingSessionTracker struct {
	mu *sync.Mutex
	// sesisonID -> pending
	sess map[string]*pendingSessionMeta
}

var _ Tracker = (*pendingSessionTracker)(nil)

func NewPendingSessionTracker() *pendingSessionTracker {
	return &pendingSessionTracker{
		mu:   &sync.Mutex{},
		sess: map[string]*pendingSessionMeta{},
	}
}

func (p *pendingSessionTracker) Inc(sessionID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	meta, ok := p.sess[sessionID]
	if !ok {
		p.sess[sessionID] = NewPendingSessionMeta(sessionID)
		return
	}
	meta.count++
}

func (p *pendingSessionTracker) Dec(sessionID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	meta, ok := p.sess[sessionID]
	if !ok {
		panic("decrement : session tracker was not already tracking this stream")
	}
	meta.count--
	if meta.count == 0 {
		meta.Close()
		delete(p.sess, sessionID)
	}
}

func (p *pendingSessionTracker) SetBindingRequest(sessionID string, req *SessionBindingCode) {
	p.mu.Lock()
	defer p.mu.Unlock()
	meta, ok := p.sess[sessionID]
	if !ok {
		return
	}
	meta.bindingRequest.Resolve(req)
}

func (p *pendingSessionTracker) SetRecords(sessionID string, rec []*databroker.Record) {
	p.mu.Lock()
	defer p.mu.Unlock()
	meta, ok := p.sess[sessionID]
	if !ok {
		return
	}
	meta.rec.Resolve(rec)
}

func (p *pendingSessionTracker) GetBindingRequest(sessionID string) (<-chan *SessionBindingCode, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	meta, ok := p.sess[sessionID]
	if !ok {
		return nil, false
	}
	return meta.bindingRequest.Get(), true
}

func (p *pendingSessionTracker) WatchBindingRequest(sessionID string) (<-chan *SessionBindingCode, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	meta, ok := p.sess[sessionID]
	if !ok {
		return nil, false
	}
	return meta.bindingRequest.Watch(), true
}

func (p *pendingSessionTracker) GetRecords(sessionID string) (<-chan []*databroker.Record, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	meta, ok := p.sess[sessionID]
	if !ok {
		return nil, false
	}
	return meta.rec.Get(), true
}

type pendingSessionMeta struct {
	sessionID      string
	bindingRequest *pendingValue[*SessionBindingCode]
	count          int
	rec            *pendingValue[[]*databroker.Record]
}

func (p *pendingSessionMeta) Close() {
	p.bindingRequest.Close()
	p.rec.Close()
}

func NewPendingSessionMeta(sessionID string) *pendingSessionMeta {
	return &pendingSessionMeta{
		sessionID:      sessionID,
		bindingRequest: NewPending[*SessionBindingCode](),
		rec:            NewPending[[]*databroker.Record](),
		count:          1,
	}
}
