package cache

import (
	"context"
	"errors"

	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/directory"
)

// RefreshUser refreshes a user's directory information.
func (c *Cache) RefreshUser(ctx context.Context, req *directory.RefreshUserRequest) (*emptypb.Empty, error) {
	c.mu.Lock()
	dp := c.directoryProvider
	c.mu.Unlock()

	if dp == nil {
		return nil, errors.New("no directory provider is available for refresh")
	}

	u, err := dp.User(ctx, req.GetUserId(), req.GetAccessToken())
	if err != nil {
		return nil, err
	}

	any, err := anypb.New(u)
	if err != nil {
		return nil, err
	}

	_, err = c.dataBrokerServer.Set(ctx, &databroker.SetRequest{
		Type: any.GetTypeUrl(),
		Id:   u.GetId(),
		Data: any,
	})
	if err != nil {
		return nil, err
	}

	return new(emptypb.Empty), nil
}
