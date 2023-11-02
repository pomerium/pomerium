package fileutil

import (
	"context"
	"sync"

	"github.com/fsnotify/fsnotify"
	"namespacelabs.dev/go-filenotify"

	"github.com/pomerium/pomerium/internal/chanutil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/signal"
)

// A Watcher watches files for changes.
type Watcher struct {
	*signal.Signal

	mu             sync.Mutex
	watching       map[string]struct{}
	eventWatcher   filenotify.FileWatcher
	pollingWatcher filenotify.FileWatcher
}

// NewWatcher creates a new Watcher.
func NewWatcher() *Watcher {
	return &Watcher{
		Signal:   signal.New(),
		watching: make(map[string]struct{}),
	}
}

// Watch updates the watched file paths.
func (watcher *Watcher) Watch(ctx context.Context, filePaths []string) {
	watcher.mu.Lock()
	defer watcher.mu.Unlock()

	watcher.initLocked(ctx)

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

		if watcher.eventWatcher != nil {
			err := watcher.eventWatcher.Add(filePath)
			if err != nil {
				log.Error(ctx).Err(err).Str("file", filePath).Msg("fileutil/watcher: failed to add file to polling-based file watcher")
			}
		}

		if watcher.pollingWatcher != nil {
			err := watcher.pollingWatcher.Add(filePath)
			if err != nil {
				log.Error(ctx).Err(err).Str("file", filePath).Msg("fileutil/watcher: failed to add file to polling-based file watcher")
			}
		}
	}

	for _, filePath := range remove {
		delete(watcher.watching, filePath)

		if watcher.eventWatcher != nil {
			err := watcher.eventWatcher.Remove(filePath)
			if err != nil {
				log.Error(ctx).Err(err).Str("file", filePath).Msg("fileutil/watcher: failed to remove file from event-based file watcher")
			}
		}

		if watcher.pollingWatcher != nil {
			err := watcher.pollingWatcher.Remove(filePath)
			if err != nil {
				log.Error(ctx).Err(err).Str("file", filePath).Msg("fileutil/watcher: failed to remove file from polling-based file watcher")
			}
		}
	}
}

func (watcher *Watcher) initLocked(ctx context.Context) {
	if watcher.eventWatcher != nil || watcher.pollingWatcher != nil {
		return
	}

	if watcher.eventWatcher == nil {
		var err error
		watcher.eventWatcher, err = filenotify.NewEventWatcher()
		if err != nil {
			log.Error(ctx).Err(err).Msg("fileutil/watcher: failed to create event-based file watcher")
		}
	}
	if watcher.pollingWatcher == nil {
		watcher.pollingWatcher = filenotify.NewPollingWatcher(nil)
	}

	var errors <-chan error = watcher.pollingWatcher.Errors()          //nolint
	var events <-chan fsnotify.Event = watcher.pollingWatcher.Events() //nolint

	if watcher.eventWatcher != nil {
		errors = chanutil.Merge(errors, watcher.eventWatcher.Errors())
		events = chanutil.Merge(events, watcher.eventWatcher.Events())
	}

	// log errors
	go func() {
		for err := range errors {
			log.Error(ctx).Err(err).Msg("fileutil/watcher: file notification error")
		}
	}()

	// handle events
	go func() {
		for evts := range chanutil.Batch(events) {
			for _, evt := range evts {
				log.Info(ctx).Str("name", evt.Name).Str("op", evt.Op.String()).Msg("fileutil/watcher: file notification event")
			}
			watcher.Broadcast(ctx)
		}
	}()
}
