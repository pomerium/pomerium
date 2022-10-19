package fileutil

import (
	"context"
	"sync"

	"github.com/fsnotify/fsnotify"
	"github.com/rs/zerolog"
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

// Add adds a new watch.
func (watcher *Watcher) Add(filePath string) {
	watcher.mu.Lock()
	defer watcher.mu.Unlock()

	// already watching
	if _, ok := watcher.watching[filePath]; ok {
		return
	}

	ctx := log.WithContext(context.Background(), func(c zerolog.Context) zerolog.Context {
		return c.Str("watch_file", filePath)
	})
	watcher.initLocked(ctx)

	if watcher.eventWatcher != nil {
		if err := watcher.eventWatcher.Add(filePath); err != nil {
			log.Error(ctx).Msg("fileutil/watcher: failed to watch file with event-based file watcher")
		}
	}

	if watcher.pollingWatcher != nil {
		if err := watcher.pollingWatcher.Add(filePath); err != nil {
			log.Error(ctx).Msg("fileutil/watcher: failed to watch file with polling-based file watcher")
		}
	}
}

// Clear removes all watches.
func (watcher *Watcher) Clear() {
	watcher.mu.Lock()
	defer watcher.mu.Unlock()

	if w := watcher.eventWatcher; w != nil {
		_ = watcher.pollingWatcher.Close()
		watcher.eventWatcher = nil
	}

	if w := watcher.pollingWatcher; w != nil {
		_ = watcher.pollingWatcher.Close()
		watcher.pollingWatcher = nil
	}

	watcher.watching = make(map[string]struct{})
}

func (watcher *Watcher) initLocked(ctx context.Context) {
	if watcher.eventWatcher != nil || watcher.pollingWatcher != nil {
		return
	}

	if watcher.eventWatcher == nil {
		var err error
		watcher.eventWatcher, err = filenotify.NewEventWatcher()
		if err != nil {
			log.Error(ctx).Msg("fileutil/watcher: failed to create event-based file watcher")
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
