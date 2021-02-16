package registry

import (
	"context"
	"sync"
	"time"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/signal"
	pb "github.com/pomerium/pomerium/pkg/grpc/registry"

	"github.com/golang/protobuf/ptypes"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type inMemoryServer struct {
	ttl time.Duration
	// onchange is used to broadcast changes to listeners
	onchange *signal.Signal
	// regs is {service,endpoint} -> expiration time mapping
	regs map[inMemoryKey]*timestamppb.Timestamp
	// mu holds lock for regs
	mu sync.RWMutex
}

type inMemoryKey struct {
	kind     pb.ServiceKind
	endpoint string
}

// NewInMemoryServer constructs new registry tracking service that operates in RAM
// as such, it is not usable for multi-node deployment where REDIS or other alternative should be used
func NewInMemoryServer(ctx context.Context, ttl time.Duration) pb.RegistryServer {
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
			log.Info().Msg("grpc.service_registry.PeriodicCheck/Stop")
			return
		case <-time.After(after):
			log.Debug().Msgf("grpc.service_registry.PeriodicCheck/Run %+v", s.getServices(nil))
			if s.lockAndRmExpired() {
				s.onchange.Broadcast()
			}
		}
	}
}

// Report is periodically sent by each service to confirm it is still serving with the registry
// data is persisted with a certain TTL
func (s *inMemoryServer) Report(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	updated, err := s.lockAndReport(req.Services)
	if err != nil {
		return nil, err
	}

	if updated {
		s.onchange.Broadcast()
	}

	return &pb.RegisterResponse{CallBackAfter: ptypes.DurationProto(s.ttl / callAfterTTLFactor)}, nil
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
	expires, err := ptypes.TimestampProto(time.Now().Add(s.ttl))
	if err != nil {
		return false, err
	}

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
func (s *inMemoryServer) List(ctx context.Context, req *pb.ListRequest) (*pb.ServiceList, error) {
	return &pb.ServiceList{Services: s.getServices(kindsMap(req.Kinds))}, nil
}

func kindsMap(kinds []pb.ServiceKind) map[pb.ServiceKind]bool {
	out := make(map[pb.ServiceKind]bool, len(kinds))
	for _, k := range kinds {
		out[k] = true
	}
	return out
}

// Watch returns a stream of updates
// for the simplicity of consumer its delivered as full snapshots
func (s *inMemoryServer) Watch(req *pb.ListRequest, srv pb.Registry_WatchServer) error {
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

func (s *inMemoryServer) getServiceUpdates(ctx context.Context, kinds map[pb.ServiceKind]bool, updates chan struct{}) ([]*pb.Service, error) {
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
		} else if _, exists := kinds[k.kind]; !exists {
			continue
		}
		out = append(out, &pb.Service{Kind: k.kind, Endpoint: k.endpoint})
	}
	return out
}
