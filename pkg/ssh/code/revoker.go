package code

import (
	"context"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/storage"
)

type revoker struct {
	clientB databroker.ClientGetter
}

var _ Revoker = (*revoker)(nil)

func NewRevoker(client databroker.ClientGetter) Revoker {
	return &revoker{
		clientB: client,
	}
}

func (r *revoker) RevokeCode(ctx context.Context, codeID CodeID) error {
	_, err := storage.DeleteDataBrokerRecord(ctx, r.clientB.GetDataBrokerServiceClient(), "type.googleapis.com/session.SessionBindingRequest", string(codeID))
	return err
}
