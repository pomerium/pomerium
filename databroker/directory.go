package databroker

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/pomerium/pomerium/internal/directory/directoryerrors"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/directory"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

// RefreshUser refreshes a user's directory information.
func (c *DataBroker) RefreshUser(ctx context.Context, req *directory.RefreshUserRequest) (*emptypb.Empty, error) {
	c.mu.Lock()
	dp := c.directoryProvider
	c.mu.Unlock()

	if dp == nil {
		return nil, errors.New("no directory provider is available for refresh")
	}

	u, err := dp.User(ctx, req.GetUserId(), req.GetAccessToken())
	// if the returned error signals we should prefer existing information
	if errors.Is(err, directoryerrors.ErrPreferExistingInformation) {
		_, err = c.dataBrokerServer.Get(ctx, &databroker.GetRequest{
			Type: protoutil.GetTypeURL(new(directory.User)),
			Id:   req.GetUserId(),
		})
		switch status.Code(err) {
		case codes.OK:
			return new(emptypb.Empty), nil
		case codes.NotFound: // go ahead and save the user that was returned
		default:
			return nil, fmt.Errorf("databroker: error retrieving existing user record for refresh: %w", err)
		}
	} else if err != nil {
		return nil, err
	}

	any := protoutil.NewAny(u)
	_, err = c.dataBrokerServer.Put(ctx, &databroker.PutRequest{
		Records: []*databroker.Record{{
			Type: any.GetTypeUrl(),
			Id:   u.GetId(),
			Data: any,
		}},
	})
	if err != nil {
		return nil, err
	}

	return new(emptypb.Empty), nil
}
