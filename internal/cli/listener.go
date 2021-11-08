package cli

import (
	"context"
	"errors"
)

type listenerEntry struct {
	context.CancelFunc
	addr string
}

type listenerStatus map[string]listenerEntry

var (
	errAlreadyLocked = errors.New("already locked")
	errNotLocked     = errors.New("not locked")
)

func newListenerStatus() ListenerStatus {
	return listenerStatus(make(map[string]listenerEntry))
}

func (l listenerStatus) SetListening(id string, cancel context.CancelFunc, addr string) error {
	if _, there := l[id]; there {
		return errAlreadyLocked
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
		return errNotLocked
	}
	rec.CancelFunc()
	delete(l, id)
	return nil
}
