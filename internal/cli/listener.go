package cli

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/tcptunnel"
	pb "github.com/pomerium/pomerium/pkg/grpc/cli"
)

// TunnelProvider abstracts listener from configuration management
type TunnelProvider interface {
	NewTunnel(id string) (*tcptunnel.Tunnel, string, error)
}

type listenerServer struct {
	sync.Mutex
	TunnelProvider
	active map[string]context.CancelFunc
}

// NewListener returns new listener server
func NewListener(tp TunnelProvider) pb.ListenerServer {
	return &listenerServer{
		TunnelProvider: tp,
		active:         make(map[string]context.CancelFunc),
	}
}

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

	ctx, cancel := context.WithCancel(context.Background())
	cancelTun := func(id string) func() {
		return func() {
			cancel()
			s.Lock()
			delete(s.active, id)
			s.Unlock()
		}
	}

	for _, id := range ids {
		if s.active[id] != nil {
			status.Errors[id] = "already connected"
			continue
		}
		tun, listenAddr, err := s.NewTunnel(id)
		if err != nil {
			status.Errors[id] = err.Error()
			continue
		}
		addr, err := listen(ctx, tun, listenAddr)
		if err != nil {
			status.Errors[id] = err.Error()
			continue
		}
		status.Active[id] = addr.String()
		s.active[id] = cancelTun(id)
	}

	return status, nil
}

func (s *listenerServer) disconnectLocked(ids []string) (*pb.ListenerStatus, error) {
	errs := make(map[string]string, len(ids))
	for _, id := range ids {
		fn, ok := s.active[id]
		if !ok {
			errs[id] = "was not active"
		}
		fn()
		delete(s.active, id)
	}

	return &pb.ListenerStatus{
		Errors: errs,
	}, nil
}

func (s *listenerServer) StatusUpdates(*pb.Selector, pb.Listener_StatusUpdatesServer) error {
	return status.Errorf(codes.Unimplemented, "method StatusUpdates not implemented")
}

func listen(ctx context.Context, tun *tcptunnel.Tunnel, listenerAddress string) (net.Addr, error) {
	li, err := net.Listen("tcp", listenerAddress)
	if err != nil {
		return nil, err
	}

	go acceptLoop(ctx, li, tun)
	return li.Addr(), nil
}

func acceptLoop(ctx context.Context, li net.Listener, tun *tcptunnel.Tunnel) {
	defer li.Close()

	bo := backoff.NewExponentialBackOff()
	bo.MaxElapsedTime = 0

	for {
		conn, err := li.Accept()
		if err != nil {
			// canceled, so ignore the error and return
			if ctx.Err() != nil {
				return
			}

			if nerr, ok := err.(net.Error); ok && nerr.Temporary() {
				log.Warn(ctx).Err(err).Msg("failed to accept local connection")
				select {
				case <-time.After(bo.NextBackOff()):
				case <-ctx.Done():
					return
				}
				continue
			}
			return
		}
		bo.Reset()

		go func() {
			defer func() { _ = conn.Close() }()

			err := tun.Run(ctx, conn)
			if err != nil {
				log.Error(ctx).Err(err).Msg("error serving local connection")
			}
		}()
	}
}
