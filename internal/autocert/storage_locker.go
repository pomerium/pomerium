package autocert

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/google/uuid"
)

type Locker interface {
	certmagic.Locker
	certmagic.TryLocker
}

const (
	lockDuration     = time.Second * 30
	lockPollInterval = time.Second
)

type lockState struct {
	ID      string
	Expires time.Time
}

type locker struct {
	store  func(ctx context.Context, key string, value []byte) error
	load   func(ctx context.Context, key string) ([]byte, error)
	delete func(ctx context.Context, key string) error
}

// NewLocker creates a new locker backed by store, load, and delete functions.
func NewLocker(
	storeFunc func(ctx context.Context, key string, value []byte) error,
	loadFunc func(ctx context.Context, key string) ([]byte, error),
	deleteFunc func(ctx context.Context, key string) error,
) Locker {
	return &locker{store: storeFunc, load: loadFunc, delete: deleteFunc}
}

func (l *locker) Lock(ctx context.Context, name string) error {
	for {
		ok, err := l.TryLock(ctx, name)
		if err != nil {
			return err
		} else if ok {
			return nil
		}

		// wait
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case <-time.After(lockPollInterval):
		}
	}
}

func (l *locker) TryLock(ctx context.Context, name string) (bool, error) {
	key := fmt.Sprintf("locks/%s", name)
	lockID := uuid.NewString()

	for {
		data, err := l.load(ctx, key)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return false, err
		}

		var ls lockState
		if json.Unmarshal(data, &ls) == nil {
			if ls.ID == lockID {
				return true, nil
			} else if ls.Expires.Before(time.Now()) {
				// ignore the existing lock and take it ourselves
			} else {
				return false, nil
			}
		}

		ls.ID = lockID
		ls.Expires = time.Now().Add(lockDuration)
		data, err = json.Marshal(ls)
		if err != nil {
			return false, err
		}

		err = l.store(ctx, key, data)
		if err != nil {
			return false, err
		}
	}
}

func (l *locker) Unlock(ctx context.Context, name string) error {
	key := fmt.Sprintf("locks/%s", name)
	return l.delete(ctx, key)
}
