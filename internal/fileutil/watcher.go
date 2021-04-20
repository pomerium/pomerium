package fileutil

import (
	"context"
	"sync"

	"github.com/rjeczalik/notify"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/signal"
)

// A Watcher watches files for changes.
type Watcher struct {
	*signal.Signal
	mu        sync.Mutex
	filePaths map[string]chan notify.EventInfo
}

// NewWatcher creates a new Watcher.
func NewWatcher() *Watcher {
	return &Watcher{
		Signal:    signal.New(),
		filePaths: map[string]chan notify.EventInfo{},
	}
}

// Add adds a new watch.
func (watcher *Watcher) Add(filePath string) {
	watcher.mu.Lock()
	defer watcher.mu.Unlock()

	ctx := context.TODO()

	// already watching
	if _, ok := watcher.filePaths[filePath]; ok {
		return
	}

	ch := make(chan notify.EventInfo, 1)
	go func() {
		for evt := range ch {
			log.Info(ctx).Str("path", evt.Path()).Str("event", evt.Event().String()).Msg("filemgr: detected file change")
			watcher.Signal.Broadcast()
		}
	}()
	err := notify.Watch(filePath, ch, notify.All)
	if err != nil {
		log.Error(ctx).Err(err).Str("path", filePath).Msg("filemgr: error watching file path")
		notify.Stop(ch)
		close(ch)
		return
	}
	log.Debug(ctx).Str("path", filePath).Msg("filemgr: watching file for changes")

	watcher.filePaths[filePath] = ch
}

// Clear removes all watches.
func (watcher *Watcher) Clear() {
	watcher.mu.Lock()
	defer watcher.mu.Unlock()

	for filePath, ch := range watcher.filePaths {
		notify.Stop(ch)
		close(ch)
		delete(watcher.filePaths, filePath)
	}
}
