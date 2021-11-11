package cli

import (
	"context"
	"errors"

	pb "github.com/pomerium/pomerium/pkg/grpc/cli"
)

type listenerStatusEntry struct {
	context.CancelFunc
	pb.ListenerStatus
}

type listenerStatus map[string]listenerStatusEntry

func newListenerStatus() ListenerStatus {
	return listenerStatus(make(map[string]listenerStatusEntry))
}

func (l listenerStatus) SetListening(id string, cancel context.CancelFunc, addr string) error {
	if _, there := l[id]; there {
		return errAlreadyListening
	}

	l[id] = listenerStatusEntry{cancel, pb.ListenerStatus{
		Listening:  true,
		ListenAddr: &addr,
	}}
	return nil
}

func (l listenerStatus) GetListenerStatus(id string) *pb.ListenerStatus {
	rec, there := l[id]
	if !there {
		return &pb.ListenerStatus{}
	}
	return &rec.ListenerStatus
}

func (l listenerStatus) SetNotListening(id string) error {
	rec, there := l[id]
	if !there || !rec.Listening || rec.CancelFunc == nil {
		return errNotListening
	}
	rec.CancelFunc()
	delete(l, id)
	return nil
}

func (l listenerStatus) SetListenerError(id string, err error) error {
	if _, there := l[id]; there {
		return errors.New("invalid state")
	}
	txt := err.Error()
	l[id] = listenerStatusEntry{
		ListenerStatus: pb.ListenerStatus{LastError: &txt},
	}
	return nil
}
