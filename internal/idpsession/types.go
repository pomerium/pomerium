package idpsession

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

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

const maxPatchRequestSize = 1024 * 1024

type boundRef struct {
	typeURL      string
	idpSessionID string
}

type ChangeSetType = uint8

// there's an implicit ordering here representing priority of operations
// (delete > revoke > propagate)
const (
	// changePropagate copies idpsession state onto the dependent records bound to it
	changePropagate ChangeSetType = iota + 1
	// changeRevoke deletes a binding and the record bound to it
	changeRevoke
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

type ChangeQueue interface {
	Schedule(context.Context, ...ChangeSet)
	ProcessDue(time.Time, func([]ChangeSet) error) error
	Reset()
}

//nolint:revive
type IDPSessionTracker interface {
	IDPSession(string) (*idpsession.IDPSession, bool)
	IDPSessionsBySID(string) []*idpsession.IDPSession
	IDPSessionsByUser(string) []*idpsession.IDPSession
	PutIDPSession(*idpsession.IDPSession, time.Time)
	DeleteIDPSession(string, time.Time)
	PutBinding(*idpsession.Binding, time.Time)
	DeleteBinding(string, time.Time)
}

// reconciler needs to update the state directly to identity index while
// it holds the lock
type ReconcilerOps interface {
	idpSessionLocked(string) (*idpsession.IDPSession, bool)
	bindingLocked(string) (*idpsession.Binding, bool)
	bindingsByIDPSessionLocked(string) []*idpsession.Binding
	dropBindingLocked(string)
}

type UserTracker interface {
	GetUser(string) *user.User
	PutUser(*user.User)
	DeleteUser(string)
}

type IdentityIndex interface {
	sync.Locker
	IDPSessionTracker
	UserTracker
	ReconcilerOps

	Reset()
}

type IdleTracker interface {
	ProcessDue(time.Time, func([]string) error) error
	Set(id string, deadline time.Time)
	Clear(id string)
	Reset()
}

// DanglingTracker is used to schedule deletes for dangling (binding, bound)
// record pairs.
type DanglingTracker interface {
	UpdateBindings(context.Context, *idpsession.Binding)
	CheckRecord(context.Context, *databroker.Record)
	ScheduleDangling(context.Context)
	Clear(context.Context)
}

func constructPatchedBoundRecord(typeURL string, id string, sess *idpsession.IDPSession) (*databroker.Record, error) {
	applier := idpSessionApplier{IDPSession: sess}
	switch typeURL {
	case sessionTypeURL:
		s := &session.Session{Id: id}
		applier.ApplyToSession(s)
		return databroker.NewRecord(s), nil
	case mcpRefreshTokenTypeURL:
		token := &oauth21.MCPRefreshToken{Id: id}
		applier.ApplyToMCP(token)
		return databroker.NewRecord(token), nil
	default:
		return nil, fmt.Errorf("%s not yet supported as a binding dependency", typeURL)
	}
}

func newBoundRecord(typeURL string, id string) (*databroker.Record, error) {
	if !slices.Contains(boundRecordTypes, typeURL) {
		return nil, fmt.Errorf("%s not yet supported as a binding dependency", typeURL)
	}
	return &databroker.Record{
		Id:   id,
		Type: typeURL,
	}, nil
}

func newRecord(typeURL string, id string) (*databroker.Record, error) {
	if typeURL == bindingTypeURL {
		return databroker.NewRecord(&idpsession.Binding{Id: id}), nil
	}
	return newBoundRecord(typeURL, id)
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
