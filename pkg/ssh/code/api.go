package code

import (
	"context"
	"time"

	"github.com/pomerium/pomerium/pkg/grpc/session"
)

const (
	defaultIssuerCodeTTL = time.Minute * 15

	queryLimit = 100000
)

type (
	//nolint:revive
	CodeID    string
	BindingID string
)

type Issuer interface {
	Reader
	Revoker

	IssueCode() CodeID
	AssociateCode(context.Context, CodeID, *session.SessionBindingRequest) (CodeID, error)
	OnCodeDecision(context.Context, CodeID) <-chan Status
	CodeTTL() time.Duration
	Done() chan struct{}
}

type Reader interface {
	GetBindingRequest(context.Context, CodeID) (*session.SessionBindingRequest, bool)
}

type Revoker interface {
	RevokeCode(context.Context, CodeID) error
}

type ReaderRevoker interface {
	Reader
	Revoker
}
