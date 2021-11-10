package cli

import (
	"context"
)

type listenerEntry struct {
	context.CancelFunc
	addr string
}

type listenerStatus map[string]listenerEntry

func newListenerStatus() ListenerStatus {
	return listenerStatus(make(map[string]listenerEntry))
}

func (l listenerStatus) SetListening(id string, cancel context.CancelFunc, addr string) error {
	if _, there := l[id]; there {
		return errAlreadyListening
	}

	l[id] = listenerEntry{cancel, addr}
	return nil
}

func (l listenerStatus) IsListening(id string) (string, bool) {
	rec, there := l[id]
	return rec.addr, there
}

func (l listenerStatus) SetNotListening(id string) error {
	rec, there := l[id]
	if !there {
		return errNotListening
	}
	rec.CancelFunc()
	delete(l, id)
	return nil
}
