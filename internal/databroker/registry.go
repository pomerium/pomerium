package databroker

import (
	"context"
	"fmt"
	"io"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/registry"
	"github.com/pomerium/pomerium/internal/registry/inmemory"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
	registrypb "github.com/pomerium/pomerium/pkg/grpc/registry"
	"github.com/pomerium/pomerium/pkg/storage"
)

type registryWatchServer struct {
	registrypb.Registry_WatchServer
	ctx context.Context
}

func (stream registryWatchServer) Context() context.Context {
	return stream.ctx
}

// Report calls the registry Report method.
func (srv *Server) Report(ctx context.Context, req *registrypb.RegisterRequest) (*registrypb.RegisterResponse, error) {
	ctx, span := trace.StartSpan(ctx, "databroker.grpc.Report")
	defer span.End()

	r, err := srv.getRegistry(ctx)
	if err != nil {
		return nil, err
	}

	return r.Report(ctx, req)
}

// List calls the registry List method.
func (srv *Server) List(ctx context.Context, req *registrypb.ListRequest) (*registrypb.ServiceList, error) {
	ctx, span := trace.StartSpan(ctx, "databroker.grpc.List")
	defer span.End()

	r, err := srv.getRegistry(ctx)
	if err != nil {
		return nil, err
	}

	return r.List(ctx, req)
}

// Watch calls the registry Watch method.
func (srv *Server) Watch(req *registrypb.ListRequest, stream registrypb.Registry_WatchServer) error {
	ctx := stream.Context()
	ctx, span := trace.StartSpan(ctx, "databroker.grpc.Watch")
	defer span.End()

	r, err := srv.getRegistry(ctx)
	if err != nil {
		return err
	}

	return r.Watch(req, registryWatchServer{
		Registry_WatchServer: stream,
		ctx:                  ctx,
	})
}

func (srv *Server) getRegistry(ctx context.Context) (registry.Interface, error) {
	backend, err := srv.getBackend(ctx)
	if err != nil {
		return nil, err
	}

	// double-checked locking
	srv.mu.RLock()
	r := srv.registry
	srv.mu.RUnlock()
	if r == nil {
		srv.mu.Lock()
		r = srv.registry
		var err error
		if r == nil {
			r, err = srv.newRegistryLocked(ctx, backend)
			srv.registry = r
		}
		srv.mu.Unlock()
		if err != nil {
			return nil, err
		}
	}
	return r, nil
}

func (srv *Server) newRegistryLocked(ctx context.Context, backend storage.Backend) (registry.Interface, error) {
	if hasRegistryServer, ok := backend.(interface {
		RegistryServer() registrypb.RegistryServer
	}); ok {
		log.Ctx(ctx).Info().Msg("using registry via storage")
		return struct {
			io.Closer
			registrypb.RegistryServer
		}{backend, hasRegistryServer.RegistryServer()}, nil
	}

	switch srv.cfg.storageType {
	case config.StorageInMemoryName:
		log.Ctx(ctx).Info().Msg("using in-memory registry")
		return inmemory.New(ctx, srv.cfg.registryTTL), nil
	}

	return nil, fmt.Errorf("unsupported registry type: %s", srv.cfg.storageType)
}
