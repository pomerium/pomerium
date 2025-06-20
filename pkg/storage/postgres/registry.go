package postgres

import (
	"context"
	"time"

	"github.com/hashicorp/go-set/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/pomerium/pomerium/pkg/grpc/registry"
)

type registryServer struct {
	registry.UnimplementedRegistryServer
	*Backend
}

// RegistryServer returns a registry.RegistryServer for the backend.
func (backend *Backend) RegistryServer() registry.RegistryServer {
	return registryServer{Backend: backend}
}

// List lists services.
func (backend registryServer) List(
	ctx context.Context,
	req *registry.ListRequest,
) (*registry.ServiceList, error) {
	_, pool, err := backend.init(ctx)
	if err != nil {
		return nil, err
	}

	if err = backend.acquire(ctx); err != nil {
		return nil, err
	}
	defer backend.release()

	all, err := listServices(ctx, pool)
	if err != nil {
		return nil, err
	}

	res := new(registry.ServiceList)
	s := set.New[registry.ServiceKind](len(all))
	s.InsertSlice(req.GetKinds())
	for _, svc := range all {
		if s.Size() == 0 || s.Contains(svc.GetKind()) {
			res.Services = append(res.Services, svc)
		}
	}
	return res, nil
}

// Report registers services.
func (backend registryServer) Report(
	ctx context.Context,
	req *registry.RegisterRequest,
) (*registry.RegisterResponse, error) {
	_, pool, err := backend.init(ctx)
	if err != nil {
		return nil, err
	}

	if err = backend.acquire(ctx); err != nil {
		return nil, err
	}
	defer backend.release()

	for _, svc := range req.GetServices() {
		err = putService(ctx, pool, svc, time.Now().Add(backend.cfg.registryTTL))
		if err != nil {
			return nil, err
		}
	}

	err = signalServiceChange(ctx, pool)
	if err != nil {
		return nil, err
	}

	return &registry.RegisterResponse{
		CallBackAfter: durationpb.New(backend.cfg.registryTTL / 2),
	}, nil
}

// Watch watches services.
func (backend registryServer) Watch(
	req *registry.ListRequest,
	srv registry.Registry_WatchServer,
) error {
	ch := backend.onServiceChange.Bind()
	defer backend.onServiceChange.Unbind(ch)

	ticker := time.NewTicker(watchPollInterval)
	defer ticker.Stop()

	var prev *registry.ServiceList
	for i := 0; ; i++ {
		res, err := backend.List(srv.Context(), req)
		if err != nil {
			return err
		}

		if i == 0 || !proto.Equal(res, prev) {
			err = srv.Send(res)
			if err != nil {
				return err
			}
			prev = res
		}

		select {
		case <-srv.Context().Done():
			return srv.Context().Err()
		case <-ch:
		case <-ticker.C:
		}
	}
}
