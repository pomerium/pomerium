package code

import (
	"context"
	"time"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
)

const (
	DefaultCodeTTL = time.Minute * 15

	queryLimit = 100000
)

type (
	//nolint:revive
	CodeID    string
	BindingID string
)

type IdentitySessionPair struct {
	SB *session.SessionBinding
	IB *session.IdentityBinding
}

type Issuer interface {
	Reader
	Revoker

	IssueCode() CodeID
	AssociateCode(context.Context, CodeID, *session.SessionBindingRequest) (CodeID, error)
	OnCodeDecision(context.Context, CodeID) <-chan Status
	Done() chan struct{}
}

type Reader interface {
	GetBindingRequest(context.Context, CodeID) (*session.SessionBindingRequest, bool)
	GetSessionByUserID(ctx context.Context, userID string) (map[string]*IdentitySessionPair, error)
}

type Revoker interface {
	RevokeCode(context.Context, CodeID) error
	RevokeSessionBinding(context.Context, BindingID) error
	RevokeSessionBindingBySession(ctx context.Context, sessionID string) ([]*databroker.Record, error)
}

type ReaderRevoker interface {
	Reader
	Revoker
}
