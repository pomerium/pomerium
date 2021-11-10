package cli

import (
	"context"
	"io"
	"net"

	pb "github.com/pomerium/pomerium/pkg/grpc/cli"
)

func (s *server) Update(ctx context.Context, req *pb.ListenerUpdateRequest) (*pb.ListenerStatus, error) {
	s.Lock()
	defer s.Unlock()

	if req.Connected {
		return s.connectLocked(req.ConnectionIds)
	}
	return s.disconnectLocked(req.ConnectionIds)
}

func (s *server) newTunnelLocked(id string) (Tunnel, string, error) {
	if _, active := s.IsListening(id); active {
		return nil, "", errAlreadyListening
	}
	rec, there := s.byID[id]
	if !there {
		return nil, "", errNotFound
	}
	return newTunnel(rec.GetConn())
}

func (s *server) connectLocked(ids []string) (*pb.ListenerStatus, error) {
	status := &pb.ListenerStatus{
		Active: make(map[string]string, len(ids)),
		Errors: make(map[string]string, len(ids)),
	}

	for _, id := range ids {
		tun, listenAddr, err := s.newTunnelLocked(id)
		if err != nil {
			status.Errors[id] = err.Error()
			continue
		}

		ctx, cancel := context.WithCancel(context.Background())
		lc := new(net.ListenConfig)
		li, err := lc.Listen(ctx, "tcp", listenAddr)
		if err != nil {
			cancel()
			return nil, err
		}

		if err = s.SetListening(id, cancel, li.Addr().String()); err != nil {
			status.Errors[id] = err.Error()
			continue
		}
		go tunnelAcceptLoop(ctx, id, li, tun, s.EventBroadcaster)
		go onContextCancel(ctx, li)
		status.Active[id] = li.Addr().String()
	}

	return status, nil
}

func onContextCancel(ctx context.Context, cl io.Closer) {
	<-ctx.Done()
	_ = cl.Close()
}

func (s *server) disconnectLocked(ids []string) (*pb.ListenerStatus, error) {
	errs := make(map[string]string, len(ids))
	for _, id := range ids {
		if err := s.SetNotListening(id); err != nil {
			errs[id] = "was not active"
		}
	}

	return &pb.ListenerStatus{
		Errors: errs,
	}, nil
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

func (s *server) GetStatus(ctx context.Context, sel *pb.Selector) (*pb.ListenerStatus, error) {
	s.RLock()
	defer s.RUnlock()

	recs, err := s.listLocked(sel)
	if err != nil {
		return nil, err
	}

	active := make(map[string]string)
	for _, r := range recs {
		addr, listening := s.IsListening(r.GetId())
		if !listening {
			continue
		}
		active[r.GetId()] = addr
	}

	return &pb.ListenerStatus{Active: active}, nil
}
