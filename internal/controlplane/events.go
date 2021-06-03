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
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/grpc"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/events"
)

const maxEnvoyConfigurationEvents = 50

func (srv *Server) handleEnvoyConfigurationEvent(evt *events.EnvoyConfigurationEvent) {
	select {
	case srv.envoyConfigurationEvents <- evt:
	default:
		log.Warn(context.Background()).
			Interface("event", evt).
			Msg("controlplane: dropping envoy configuration event due to full channel")
	}
}

func (srv *Server) runEnvoyConfigurationEventHandler(ctx context.Context) error {
	for {
		var evt *events.EnvoyConfigurationEvent
		select {
		case <-ctx.Done():
			return ctx.Err()
		case evt = <-srv.envoyConfigurationEvents:
		}

		withGRPCBackoff(ctx, func() error {
			return srv.storeEnvoyConfigurationEvent(ctx, evt)
		})
	}
}

func (srv *Server) storeEnvoyConfigurationEvent(ctx context.Context, evt *events.EnvoyConfigurationEvent) error {
	any, err := anypb.New(evt)
	if err != nil {
		return err
	}

	client, err := srv.getDataBrokerClient(ctx)
	if err != nil {
		return err
	}

	if !srv.haveSetEnvoyConfigurationEventOptions {
		_, err = client.SetOptions(ctx, &databrokerpb.SetOptionsRequest{
			Type: any.GetTypeUrl(),
			Options: &databrokerpb.Options{
				Capacity: proto.Uint64(maxEnvoyConfigurationEvents),
			},
		})
		if err != nil {
			return err
		}
		srv.haveSetEnvoyConfigurationEventOptions = true
	}

	_, err = client.Put(ctx, &databrokerpb.PutRequest{
		Record: &databrokerpb.Record{
			Type: any.GetTypeUrl(),
			Id:   uuid.NewString(),
			Data: any,
		},
	})
	if err != nil {
		return err
	}

	return nil
}

func (srv *Server) getDataBrokerClient(ctx context.Context) (databrokerpb.DataBrokerServiceClient, error) {
	options := srv.currentConfig.Load().Options

	sharedKey, err := options.GetSharedKey()
	if err != nil {
		return nil, err
	}

	urls, err := options.GetDataBrokerURLs()
	if err != nil {
		return nil, err
	}

	cc, err := grpc.GetGRPCClientConn(ctx, "databroker", &grpc.Options{
		Addrs:                   urls,
		OverrideCertificateName: options.OverrideCertificateName,
		CA:                      options.CA,
		CAFile:                  options.CAFile,
		RequestTimeout:          options.GRPCClientTimeout,
		ClientDNSRoundRobin:     options.GRPCClientDNSRoundRobin,
		WithInsecure:            options.GetGRPCInsecure(),
		InstallationID:          options.InstallationID,
		ServiceName:             options.Services,
		SignedJWTKey:            sharedKey,
	})
	if err != nil {
		return nil, fmt.Errorf("controlplane: error creating databroker connection: %w", err)
	}
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
