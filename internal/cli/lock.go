package cli

import (
	"context"
	"errors"
)

type recordLocker map[string]context.CancelFunc

var (
	errAlreadyLocked = errors.New("already locked")
	errNotLocked     = errors.New("not locked")
)

func newRecordLocker() RecordLocker {
	return recordLocker(make(map[string]context.CancelFunc))
}

func (l recordLocker) LockRecord(id string, cancel context.CancelFunc) error {
	if _, there := l[id]; there {
		return errAlreadyLocked
	}

	l[id] = cancel
	return nil
}

func (l recordLocker) IsLocked(id string) bool {
	_, there := l[id]
	return there
}

func (l recordLocker) UnlockRecord(id string) error {
	cancel, there := l[id]
	if !there {
		return errNotLocked
	}
	cancel()
	delete(l, id)
	return nil
}
