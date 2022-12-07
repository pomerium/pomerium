package autocert

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"time"

	"github.com/google/uuid"
)

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

func (l *locker) Lock(ctx context.Context, name string) error {
	key := fmt.Sprintf("locks/%s", name)
	lockID := uuid.NewString()

	for {
		data, err := l.load(ctx, key)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}

		var ls lockState
		if json.Unmarshal(data, &ls) == nil {
			if ls.ID == lockID {
				return nil
			} else if ls.Expires.Before(time.Now()) {
				// ignore the existing lock and take it ourselves
			} else {
				// wait
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(lockPollInterval):
				}
				continue
			}
		}

		ls.ID = lockID
		ls.Expires = time.Now().Add(lockDuration)
		data, err = json.Marshal(ls)
		if err != nil {
			return err
		}

		err = l.store(ctx, key, data)
		if err != nil {
			return err
		}
	}
}

func (l *locker) Unlock(ctx context.Context, name string) error {
	key := fmt.Sprintf("locks/%s", name)
	return l.delete(ctx, key)
}
