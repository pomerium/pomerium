package pending

import (
	"context"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
)

type CodeID string
type SessionID string

type CodeWithReqBinding struct {
	Code    CodeID
	Request *session.SessionBindingRequest
}

type CodeIssuer interface {
	CodeAcessor

	IssueCode() CodeID
	AssociateCode(context.Context, CodeID, *session.SessionBindingRequest) (CodeID, error)
	OnCodeInvalid(context.Context, SessionID, CodeID) <-chan error
	OnCodeSuccess(context.Context, SessionID) <-chan []*databroker.Record
	Done() chan struct{}
}

type CodeAcessor interface {
	GetBindingRequest(context.Context, CodeID) (*session.SessionBindingRequest, bool)
	RevokeCode(context.Context, CodeID) error
	RevokeSession(ctx context.Context, sessionID string) error
	GetSessionById(ctx context.Context, userID string) (map[SessionID]*IdentitySessionPair, error)
}
