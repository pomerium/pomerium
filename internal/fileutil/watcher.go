package fileutil

import (
	"context"
	"sync"

	"namespacelabs.dev/go-filenotify"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/signal"
)

// A Watcher watches files for changes.
type Watcher struct {
	*signal.Signal

	cancelCtx context.Context
	cancel    context.CancelFunc

	mu             sync.Mutex
	watching       map[string]struct{}
	pollingWatcher filenotify.FileWatcher
}

// NewWatcher creates a new Watcher.
func NewWatcher() *Watcher {
	w := &Watcher{
		Signal:   signal.New(),
		watching: make(map[string]struct{}),
	}
	w.cancelCtx, w.cancel = context.WithCancel(context.Background())
	return w
}

// Close closes the watcher.
func (w *Watcher) Close() error {
	w.cancel()

	w.mu.Lock()
	defer w.mu.Unlock()

	var err error
	if w.pollingWatcher != nil {
		err = w.pollingWatcher.Close()
		w.pollingWatcher = nil
	}

	return err
}

// Watch updates the watched file paths.
func (w *Watcher) Watch(filePaths []string) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.initLocked()

	var add []string
	seen := map[string]struct{}{}
	for _, filePath := range filePaths {
		if _, ok := w.watching[filePath]; !ok {
			add = append(add, filePath)
		}
		seen[filePath] = struct{}{}
	}

	var remove []string
	for filePath := range w.watching {
		if _, ok := seen[filePath]; !ok {
			remove = append(remove, filePath)
		}
	}

	for _, filePath := range add {
		w.watching[filePath] = struct{}{}

		if w.pollingWatcher != nil {
			err := w.pollingWatcher.Add(filePath)
			if err != nil {
				log.Error().Err(err).Str("file", filePath).Msg("fileutil/watcher: failed to add file to polling-based file watcher")
			}
		}
	}

	for _, filePath := range remove {
		delete(w.watching, filePath)

		if w.pollingWatcher != nil {
			err := w.pollingWatcher.Remove(filePath)
			if err != nil {
				log.Error().Err(err).Str("file", filePath).Msg("fileutil/watcher: failed to remove file from polling-based file watcher")
			}
		}
	}
}

func (w *Watcher) initLocked() {
	if w.pollingWatcher != nil {
		return
	}

	if w.pollingWatcher == nil {
		w.pollingWatcher = filenotify.NewPollingWatcher(nil)
	}

	errors := w.pollingWatcher.Errors()
	events := w.pollingWatcher.Events()

	// log errors
	go func() {
		for err := range errors {
			log.Error().Err(err).Msg("fileutil/watcher: file notification error")
		}
	}()

	// handle events
	go func() {
		for evt := range events {
			log.Info().Str("name", evt.Name).Str("op", evt.Op.String()).Msg("fileutil/watcher: file notification event")
			w.Broadcast(w.cancelCtx)
		}
	}()
}
