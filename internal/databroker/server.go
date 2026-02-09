// Package databroker contains a data broker implementation.
package databroker

import (
	"context"

	"google.golang.org/grpc"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/grpc/config/configconnect"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	registrypb "github.com/pomerium/pomerium/pkg/grpc/registry"
)

// A Server implements the databroker and registry interfaces.
type Server interface {
	configconnect.ConfigServiceHandler
	databrokerpb.CheckpointServiceServer
	databrokerpb.DataBrokerServiceServer
	registrypb.RegistryServer

	OnConfigChange(ctx context.Context, cfg *config.Config)
	Stop()
}

type serverWithoutStop struct {
	Server
}

func (srv serverWithoutStop) Stop() {}

func withoutStop(srv Server) Server {
	return serverWithoutStop{srv}
}

type overridenServerStreamingServerContext[T any] struct {
	grpc.ServerStreamingServer[T]
	ctx context.Context
}

func overrideServerStreamingServerContext[T any](ctx context.Context, stream grpc.ServerStreamingServer[T]) grpc.ServerStreamingServer[T] {
	return &overridenServerStreamingServerContext[T]{
		ServerStreamingServer: stream,
		ctx:                   ctx,
	}
}

func (stream *overridenServerStreamingServerContext[T]) Context() context.Context {
	return stream.ctx
}
