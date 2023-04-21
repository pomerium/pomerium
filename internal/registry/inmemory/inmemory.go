// Package inmemory implements an in-memory registry.
package inmemory

import (
	"context"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/registry"
	"github.com/pomerium/pomerium/internal/signal"
	pb "github.com/pomerium/pomerium/pkg/grpc/registry"
)

type inMemoryServer struct {
	ttl time.Duration
	// onchange is used to broadcast changes to listeners
	onchange *signal.Signal

	// mu holds lock for regs
	mu sync.RWMutex
	// regs is {service,endpoint} -> expiration time mapping
	regs map[inMemoryKey]*timestamppb.Timestamp
}

type inMemoryKey struct {
	kind     pb.ServiceKind
	endpoint string
}

// New constructs a new registry tracking service that operates in RAM
// as such, it is not usable for multi-node deployment where REDIS or other alternative should be used
func New(ctx context.Context, ttl time.Duration) registry.Interface {
	srv := &inMemoryServer{
		ttl:      ttl,
		regs:     make(map[inMemoryKey]*timestamppb.Timestamp),
		onchange: signal.New(),
	}
	go srv.periodicCheck(ctx)
	return srv
}

func (s *inMemoryServer) periodicCheck(ctx context.Context) {
	after := s.ttl * purgeAfterTTLFactor
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(after):
			if s.lockAndRmExpired() {
				s.onchange.Broadcast(ctx)
			}
		}
	}
}

// Close closes the in memory server.
func (s *inMemoryServer) Close() error {
	return nil
}

// Report is periodically sent by each service to confirm it is still serving with the registry
// data is persisted with a certain TTL
func (s *inMemoryServer) Report(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	updated, err := s.lockAndReport(req.Services)
	if err != nil {
		return nil, err
	}

	if updated {
		s.onchange.Broadcast(ctx)
	}

	return &pb.RegisterResponse{
		CallBackAfter: durationpb.New(s.ttl / callAfterTTLFactor),
	}, nil
}

func (s *inMemoryServer) lockAndRmExpired() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.rmExpiredLocked()
}

func (s *inMemoryServer) rmExpiredLocked() bool {
	now := time.Now()
	removed := false

	for k, expires := range s.regs {
		if expires.AsTime().Before(now) {
			delete(s.regs, k)
			removed = true
		}
	}

	return removed
}

// lockAndReport acquires lock, performs an update and returns current state of services
func (s *inMemoryServer) lockAndReport(services []*pb.Service) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.reportLocked(services)
}

// reportLocked updates registration and also returns an indication whether service list was updated
func (s *inMemoryServer) reportLocked(services []*pb.Service) (bool, error) {
	expires := timestamppb.New(time.Now().Add(s.ttl))

	inserted := false
	for _, svc := range services {
		k := inMemoryKey{kind: svc.Kind, endpoint: svc.Endpoint}
		if _, present := s.regs[k]; !present {
			inserted = true
		}
		s.regs[k] = expires
	}

	removed := s.rmExpiredLocked()
	return inserted || removed, nil
}

// List returns current snapshot of the services known to the registry
func (s *inMemoryServer) List(_ context.Context, req *pb.ListRequest) (*pb.ServiceList, error) {
	if err := req.Validate(); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	return &pb.ServiceList{Services: s.getServices(kindsMap(req.Kinds))}, nil
}

func kindsMap(kinds []pb.ServiceKind) map[pb.ServiceKind]bool {
	out := make(map[pb.ServiceKind]bool, len(kinds))
	for _, k := range kinds {
		out[k] = true
	}
	return out
}

// Watch returns a stream of updates as full snapshots
func (s *inMemoryServer) Watch(req *pb.ListRequest, srv pb.Registry_WatchServer) error {
	if err := req.Validate(); err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}

	kinds := kindsMap(req.Kinds)
	ctx := srv.Context()

	updates := s.onchange.Bind()
	defer s.onchange.Unbind(updates)

	if err := srv.Send(&pb.ServiceList{Services: s.getServices(kinds)}); err != nil {
		return status.Errorf(codes.Internal, "sending initial snapshot: %v", err)
	}

	for {
		services, err := s.getServiceUpdates(ctx, kinds, updates)
		if err != nil {
			return status.Errorf(codes.Internal, "obtaining service registrations: %v", err)
		}
		if err := srv.Send(&pb.ServiceList{Services: services}); err != nil {
			return status.Errorf(codes.Internal, "sending registration snapshot: %v", err)
		}
	}
}

func (s *inMemoryServer) getServiceUpdates(ctx context.Context, kinds map[pb.ServiceKind]bool, updates chan context.Context) ([]*pb.Service, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-updates:
		return s.getServices(kinds), nil
	}
}

func (s *inMemoryServer) getServices(kinds map[pb.ServiceKind]bool) []*pb.Service {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.getServicesLocked(kinds)
}

func (s *inMemoryServer) getServicesLocked(kinds map[pb.ServiceKind]bool) []*pb.Service {
	out := make([]*pb.Service, 0, len(s.regs))
	for k := range s.regs {
		if len(kinds) == 0 {
			// all catch empty filter
		} else if _, exists := kinds[k.kind]; !exists {
			continue
		}
		out = append(out, &pb.Service{Kind: k.kind, Endpoint: k.endpoint})
	}
	return out
}
