package cli

import (
	"context"
	"io"
	"net"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/pomerium/pomerium/pkg/grpc/cli"
)

func (s *server) Update(ctx context.Context, req *pb.ListenerUpdateRequest) (*pb.ListenerStatusResponse, error) {
	s.Lock()
	defer s.Unlock()

	var fn func(ids []string) (map[string]*pb.ListenerStatus, error)
	if req.Connected {
		fn = s.connectLocked
	} else {
		fn = s.disconnectLocked
	}

	listeners, err := fn(req.GetConnectionIds())
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &pb.ListenerStatusResponse{Listeners: listeners}, nil
}

func (s *server) connectLocked(ids []string) (map[string]*pb.ListenerStatus, error) {
	listeners := make(map[string]*pb.ListenerStatus, len(ids))

	for _, id := range ids {
		status := s.GetListenerStatus(id)
		if status.Listening {
			listeners[id] = status
			continue
		}

		addr, err := s.connectTunnelLocked(id)
		if err != nil {
			txt := err.Error()
			listeners[id] = &pb.ListenerStatus{LastError: &txt}
			continue
		}

		concreteAddr := addr.String()
		listeners[id] = &pb.ListenerStatus{
			Listening:  true,
			ListenAddr: &concreteAddr,
		}
	}

	return listeners, nil
}

func (s *server) connectTunnelLocked(id string) (net.Addr, error) {
	rec, there := s.byID[id]
	if !there {
		return nil, errNotFound
	}

	tun, listenAddr, err := newTunnel(rec.GetConn())
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	lc := new(net.ListenConfig)
	li, err := lc.Listen(ctx, "tcp", listenAddr)
	if err != nil {
		cancel()
		return nil, err
	}

	if err = s.SetListening(id, cancel, li.Addr().String()); err != nil {
		return nil, err
	}
	go tunnelAcceptLoop(ctx, id, li, tun, s.EventBroadcaster)
	go onContextCancel(ctx, li)

	return li.Addr(), nil
}

func onContextCancel(ctx context.Context, cl io.Closer) {
	<-ctx.Done()
	_ = cl.Close()
}

func (s *server) disconnectLocked(ids []string) (map[string]*pb.ListenerStatus, error) {
	listeners := make(map[string]*pb.ListenerStatus, len(ids))

	for _, id := range ids {
		if err := s.SetNotListening(id); err != nil {
			txt := err.Error()
			listeners[id] = &pb.ListenerStatus{LastError: &txt}
		} else {
			listeners[id] = s.GetListenerStatus(id)
		}
	}

	return listeners, nil
}

func (s *server) StatusUpdates(req *pb.StatusUpdatesRequest, upd pb.Listener_StatusUpdatesServer) error {
	ch, err := s.Subscribe(upd.Context(), req.ConnectionId)
	if err != nil {
		return err
	}

	for u := range ch {
		if err := upd.Send(u); err != nil {
			return err
		}
	}
	return nil
}

func (s *server) GetStatus(ctx context.Context, sel *pb.Selector) (*pb.ListenerStatusResponse, error) {
	s.RLock()
	defer s.RUnlock()

	recs, err := s.listLocked(sel)
	if err != nil {
		return nil, err
	}

	listeners := make(map[string]*pb.ListenerStatus, len(recs))
	for _, r := range recs {
		listeners[r.GetId()] = s.GetListenerStatus(r.GetId())
	}

	return &pb.ListenerStatusResponse{Listeners: listeners}, nil
}
