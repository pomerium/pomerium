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

	mu             sync.Mutex
	watching       map[string]struct{}
	pollingWatcher filenotify.FileWatcher
}

// NewWatcher creates a new Watcher.
func NewWatcher() *Watcher {
	return &Watcher{
		Signal:   signal.New(),
		watching: make(map[string]struct{}),
	}
}

// Close closes the watcher.
func (watcher *Watcher) Close() error {
	watcher.mu.Lock()
	defer watcher.mu.Unlock()

	var err error
	if watcher.pollingWatcher != nil {
		err = watcher.pollingWatcher.Close()
		watcher.pollingWatcher = nil
	}

	return err
}

// Watch updates the watched file paths.
func (watcher *Watcher) Watch(filePaths []string) {
	watcher.mu.Lock()
	defer watcher.mu.Unlock()

	watcher.initLocked()

	var add []string
	seen := map[string]struct{}{}
	for _, filePath := range filePaths {
		if _, ok := watcher.watching[filePath]; !ok {
			add = append(add, filePath)
		}
		seen[filePath] = struct{}{}
	}

	var remove []string
	for filePath := range watcher.watching {
		if _, ok := seen[filePath]; !ok {
			remove = append(remove, filePath)
		}
	}

	for _, filePath := range add {
		watcher.watching[filePath] = struct{}{}

		if watcher.pollingWatcher != nil {
			err := watcher.pollingWatcher.Add(filePath)
			if err != nil {
				log.Error().Err(err).Str("file", filePath).Msg("fileutil/watcher: failed to add file to polling-based file watcher")
			}
		}
	}

	for _, filePath := range remove {
		delete(watcher.watching, filePath)

		if watcher.pollingWatcher != nil {
			err := watcher.pollingWatcher.Remove(filePath)
			if err != nil {
				log.Error().Err(err).Str("file", filePath).Msg("fileutil/watcher: failed to remove file from polling-based file watcher")
			}
		}
	}
}

func (watcher *Watcher) initLocked() {
	if watcher.pollingWatcher != nil {
		return
	}

	if watcher.pollingWatcher == nil {
		watcher.pollingWatcher = filenotify.NewPollingWatcher(nil)
	}

	errors := watcher.pollingWatcher.Errors()
	events := watcher.pollingWatcher.Events()

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
			watcher.Broadcast(context.Background())
		}
	}()
}
