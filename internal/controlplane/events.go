package controlplane

import (
	"context"
	"fmt"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/grpc"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

const maxEvents = 50

var outboundGRPCConnection = new(grpc.CachedOutboundGRPClientConn)

func (srv *Server) storeEvent(ctx context.Context, evt proto.Message) error {
	any := protoutil.NewAny(evt)

	client, err := srv.getDataBrokerClient(ctx)
	if err != nil {
		return err
	}

	if !srv.haveSetCapacity[any.GetTypeUrl()] {
		_, err = client.SetOptions(ctx, &databrokerpb.SetOptionsRequest{
			Type: any.GetTypeUrl(),
			Options: &databrokerpb.Options{
				Capacity: proto.Uint64(maxEvents),
			},
		})
		if err != nil {
			return err
		}
		srv.haveSetCapacity[any.GetTypeUrl()] = true
	}

	var id string
	if withID, ok := evt.(interface{ GetId() string }); ok {
		id = withID.GetId()
	} else {
		id = uuid.NewString()
	}

	_, err = client.Put(ctx, &databrokerpb.PutRequest{
		Records: []*databrokerpb.Record{{
			Type: any.GetTypeUrl(),
			Id:   id,
			Data: any,
		}},
	})
	if err != nil {
		return err
	}

	return nil
}

func (srv *Server) getDataBrokerClient(ctx context.Context) (databrokerpb.DataBrokerServiceClient, error) {
	cfg := srv.currentConfig.Load()

	sharedKey, err := cfg.Options.GetSharedKey()
	if err != nil {
		return nil, err
	}

	cc, err := outboundGRPCConnection.Get(context.Background(), &grpc.OutboundOptions{
		OutboundPort:   cfg.OutboundPort,
		InstallationID: cfg.Options.InstallationID,
		ServiceName:    cfg.Options.Services,
		SignedJWTKey:   sharedKey,
	})
	if err != nil {
		return nil, fmt.Errorf("controlplane: error creating databroker connection: %w", err)
	}
	_ = grpc.WaitForReady(ctx, cc, time.Second*10)
	client := databrokerpb.NewDataBrokerServiceClient(cc)
	return client, nil
}

// withGRPCBackoff runs f. If an unavailable or resource exhausted error occurs, the request will be retried.
// All other errors return immediately.
func withGRPCBackoff(ctx context.Context, f func() error) {
	bo := backoff.NewExponentialBackOff()
	bo.MaxElapsedTime = 0
	for {
		err := f()
		switch {
		case err == nil:
			return
		case status.Code(err) == codes.Unavailable,
			status.Code(err) == codes.ResourceExhausted,
			status.Code(err) == codes.DeadlineExceeded:
			log.Error(ctx).Err(err).Msg("controlplane: error storing configuration event, retrying")
			// retry
		default:
			log.Error(ctx).Err(err).Msg("controlplane: error storing configuration event")
			return
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(bo.NextBackOff()):
		}
	}
}
