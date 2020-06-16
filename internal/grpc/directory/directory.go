package directory

import (
	context "context"

	"github.com/golang/protobuf/ptypes"

	"github.com/pomerium/pomerium/internal/grpc/databroker"
)

// Get gets a directory user from the databroker.
func Get(ctx context.Context, client databroker.DataBrokerServiceClient, userID string) (*User, error) {
	any, _ := ptypes.MarshalAny(new(User))

	res, err := client.Get(ctx, &databroker.GetRequest{
		Type: any.GetTypeUrl(),
		Id:   userID,
	})
	if err != nil {
		return nil, err
	}

	var u User
	err = ptypes.UnmarshalAny(res.GetRecord().GetData(), &u)
	if err != nil {
		return nil, err
	}
	return &u, nil
}
