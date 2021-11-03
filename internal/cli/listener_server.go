package cli

import (
	"context"
	"net"
	"sync"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/pomerium/pomerium/pkg/grpc/cli"
)

type listenerServer struct {
	sync.Locker
	RecordLocker
	TunnelProvider
}

var _ pb.ListenerServer = &listenerServer{}

func (s *listenerServer) Update(ctx context.Context, req *pb.ListenerUpdateRequest) (*pb.ListenerStatus, error) {
	s.Lock()
	defer s.Unlock()

	if req.Connected {
		return s.connectLocked(req.ConnectionIds)
	}
	return s.disconnectLocked(req.ConnectionIds)
}

func (s *listenerServer) connectLocked(ids []string) (*pb.ListenerStatus, error) {
	status := &pb.ListenerStatus{
		Active: make(map[string]string, len(ids)),
		Errors: make(map[string]string, len(ids)),
	}

	for _, id := range ids {
		if s.IsLocked(id) {
			status.Errors[id] = "already connected"
			continue
		}
		tun, listenAddr, err := s.NewTunnel(id)
		if err != nil {
			status.Errors[id] = err.Error()
			continue
		}
		li, err := net.Listen("tcp", listenAddr)
		if err != nil {
			return nil, err
		}

		ctx, cancel := context.WithCancel(context.Background())
		if err = s.LockRecord(id, cancel); err != nil {
			status.Errors[id] = err.Error()
			continue
		}
		go tunnelAcceptLoop(ctx, li, tun)
		status.Active[id] = li.Addr().String()
	}

	return status, nil
}

func (s *listenerServer) disconnectLocked(ids []string) (*pb.ListenerStatus, error) {
	errs := make(map[string]string, len(ids))
	for _, id := range ids {
		if err := s.UnlockRecord(id); err != nil {
			errs[id] = "was not active"
		}
	}

	return &pb.ListenerStatus{
		Errors: errs,
	}, nil
}

func (s *listenerServer) StatusUpdates(*pb.Selector, pb.Listener_StatusUpdatesServer) error {
	return status.Errorf(codes.Unimplemented, "method StatusUpdates not implemented")
}
