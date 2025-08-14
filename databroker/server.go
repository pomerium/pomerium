// Package databroker contains the databroker service.
package databroker

import (
	"context"
	"fmt"

	oteltrace "go.opentelemetry.io/otel/trace"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/atomicutil"
	"github.com/pomerium/pomerium/internal/databroker"
	"github.com/pomerium/pomerium/internal/log"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	registrypb "github.com/pomerium/pomerium/pkg/grpc/registry"
)

// A server implements the Databroker and Registry servers.
type server struct {
	server    *databroker.Server
	sharedKey *atomicutil.Value[[]byte]

	databrokerpb.UnimplementedDataBrokerServiceServer
	registrypb.UnimplementedRegistryServer
}

// newServer creates a new databroker service server.
func newServer(ctx context.Context, tracerProvider oteltrace.TracerProvider, cfg *config.Config) (*server, error) {
	srv := &server{
		sharedKey: atomicutil.NewValue([]byte{}),
	}

	opts, err := srv.getOptions(cfg)
	if err != nil {
		return nil, err
	}

	srv.server = databroker.New(ctx, tracerProvider, opts...)
	srv.setKey(cfg)
	return srv, nil
}

// OnConfigChange updates the underlying databroker server whenever configuration is changed.
func (srv *server) OnConfigChange(ctx context.Context, cfg *config.Config) {
	opts, err := srv.getOptions(cfg)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("databroker: error updating config changes")
		return
	}

	srv.server.UpdateConfig(ctx, opts...)
	srv.setKey(cfg)
}

func (srv *server) getOptions(cfg *config.Config) ([]databroker.ServerOption, error) {
	dataBrokerStorageConnectionString, err := cfg.Options.GetDataBrokerStorageConnectionString()
	if err != nil {
		return nil, fmt.Errorf("error loading databroker storage connection string: %w", err)
	}

	return []databroker.ServerOption{
		databroker.WithStorageType(cfg.Options.DataBrokerStorageType),
		databroker.WithStorageConnectionString(dataBrokerStorageConnectionString),
	}, nil
}

func (srv *server) setKey(cfg *config.Config) {
	bs, _ := cfg.Options.GetSharedKey()
	if bs == nil {
		bs = make([]byte, 0)
	}
	srv.sharedKey.Store(bs)
}
