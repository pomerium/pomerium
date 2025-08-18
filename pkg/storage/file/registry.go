package file

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/hashicorp/go-set/v3"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	registrypb "github.com/pomerium/pomerium/pkg/grpc/registry"
)

type registryServer struct {
	registrypb.UnimplementedRegistryServer
	*Backend
}

// RegistryServer returns a registry.RegistryServer for the backend.
func (backend *Backend) RegistryServer() registrypb.RegistryServer {
	return registryServer{Backend: backend}
}

func (backend registryServer) List(
	_ context.Context,
	req *registrypb.ListRequest,
) (*registrypb.ServiceList, error) {
	var svcs []*registrypb.Service
	err := backend.withReadOnlyTransaction(func(_ readOnlyTransaction) error {
		svcs = backend.registryServiceIndex.list(time.Now())
		return nil
	})
	if err != nil {
		return nil, err
	}

	if len(req.GetKinds()) > 0 {
		lookup := set.From(req.GetKinds())
		svcs = slices.DeleteFunc(svcs, func(svc *registrypb.Service) bool {
			return !lookup.Contains(svc.GetKind())
		})
	}

	return &registrypb.ServiceList{Services: svcs}, nil
}

func (backend registryServer) Report(
	ctx context.Context,
	req *registrypb.RegisterRequest,
) (*registrypb.RegisterResponse, error) {
	ttl := time.Second * 30
	err := backend.withReadWriteTransaction(func(tx *readWriteTransaction) error {
		tx.onCommit(func() { backend.onServiceChange.Broadcast(ctx) })
		return backend.putRegistryServicesLocked(tx, req.GetServices(), time.Second*30)
	})
	if err != nil {
		return nil, err
	}
	return &registrypb.RegisterResponse{CallBackAfter: durationpb.New(ttl)}, nil
}

func (backend registryServer) Watch(
	req *registrypb.ListRequest,
	stream grpc.ServerStreamingServer[registrypb.ServiceList],
) error {
	changed := backend.onServiceChange.Bind()
	defer backend.onRecordChange.Unbind(changed)

	var previous *registrypb.ServiceList
	for {
		current, err := backend.List(stream.Context(), req)
		if err != nil {
			return err
		}

		// only send the new list if it changed
		if !proto.Equal(current, previous) {
			err = stream.Send(current)
			if err != nil {
				return err
			}
			previous = current
		}

		select {
		case <-stream.Context().Done():
			return context.Cause(stream.Context())
		case <-changed:
		}
	}
}

func (backend *Backend) putRegistryServicesLocked(tx *readWriteTransaction, svcs []*registrypb.Service, ttl time.Duration) error {
	now := time.Now()
	// update the services in pebble
	for _, svc := range svcs {
		err := registryServiceKeySpace.set(tx, registryServiceNode{
			kind:      svc.GetKind(),
			endpoint:  svc.GetEndpoint(),
			expiresAt: now.Add(ttl),
		})
		if err != nil {
			return fmt.Errorf("pebble: error setting registry service: %w", err)
		}
	}
	// if the registry services are successfully written, update the index
	tx.onCommit(func() {
		for _, svc := range svcs {
			backend.registryServiceIndex.add(svc, now, ttl)
		}
	})
	return nil
}
