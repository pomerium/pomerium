package databroker

import (
	"context"
	"fmt"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/registry"
	"github.com/pomerium/pomerium/internal/registry/inmemory"
	"github.com/pomerium/pomerium/internal/registry/redis"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
	registrypb "github.com/pomerium/pomerium/pkg/grpc/registry"
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

	r, err := srv.getRegistry()
	if err != nil {
		return nil, err
	}

	return r.Report(ctx, req)
}

// List calls the registry List method.
func (srv *Server) List(ctx context.Context, req *registrypb.ListRequest) (*registrypb.ServiceList, error) {
	ctx, span := trace.StartSpan(ctx, "databroker.grpc.List")
	defer span.End()

	r, err := srv.getRegistry()
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

	r, err := srv.getRegistry()
	if err != nil {
		return err
	}

	return r.Watch(req, registryWatchServer{
		Registry_WatchServer: stream,
		ctx:                  ctx,
	})
}

func (srv *Server) getRegistry() (registry.Interface, error) {
	// double-checked locking
	srv.mu.RLock()
	r := srv.registry
	srv.mu.RUnlock()
	if r == nil {
		srv.mu.Lock()
		r = srv.registry
		var err error
		if r == nil {
			r, err = srv.newRegistryLocked()
			srv.registry = r
		}
		srv.mu.Unlock()
		if err != nil {
			return nil, err
		}
	}
	return r, nil
}

func (srv *Server) newRegistryLocked() (registry.Interface, error) {
	ctx := context.Background()

	switch srv.cfg.storageType {
	case config.StorageInMemoryName:
		log.Info(ctx).Msg("using in-memory registry")
		return inmemory.New(ctx, srv.cfg.registryTTL), nil
	case config.StorageRedisName:
		log.Info(ctx).Msg("using redis registry")
		r, err := redis.New(
			srv.cfg.storageConnectionString,
			redis.WithTLSConfig(srv.getTLSConfigLocked(ctx)),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create new redis registry: %w", err)
		}
		return r, nil
	}

	return nil, fmt.Errorf("unsupported registry type: %s", srv.cfg.storageType)
}
