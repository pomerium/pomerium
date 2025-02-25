package fileutil

import (
	"cmp"
	"context"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/hashicorp/go-set/v3"
	"github.com/zeebo/xxh3"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/signal"
)

const (
	pollingInterval = time.Millisecond * 200
)

type watchedFile struct {
	path    string
	size    int64
	modTime int64
	hash    uint64
	force   bool // indicates that the next check should compute the hash of the file as well
}

func newWatchedFile(path string) *watchedFile {
	return &watchedFile{path: path, force: true}
}

func (wf *watchedFile) check() (changed bool) {
	fi, _ := os.Stat(wf.path)
	changed = swap(&wf.size, getFileSize(fi)) || changed
	changed = swap(&wf.modTime, getFileModTime(fi)) || changed

	// if the file size or mod time has changed, re-compute the file contents hash
	if changed || wf.force {
		changed = swap(&wf.hash, hashFile(wf.path))
		wf.force = false
	}

	return changed
}

// A Watcher watches files for changes.
type Watcher struct {
	*signal.Signal

	cancelCtx context.Context
	cancel    context.CancelFunc

	mu             sync.Mutex
	notifyWatcher  *fsnotify.Watcher
	filePaths      []string
	files          map[string]*watchedFile
	directoryPaths []string
	directories    map[string]struct{}
}

// NewWatcher creates a new Watcher.
func NewWatcher() *Watcher {
	w := &Watcher{
		Signal:      signal.New(),
		files:       map[string]*watchedFile{},
		directories: map[string]struct{}{},
	}
	w.cancelCtx, w.cancel = context.WithCancel(context.Background())

	var err error
	w.notifyWatcher, err = fsnotify.NewWatcher()
	if err != nil {
		log.Error().Err(err).Msg("fileutil/watcher: file system notifications disabled")
	}

	go w.handlePolling()
	go w.handleNotifications()

	return w
}

// Close closes the watcher.
func (w *Watcher) Close() error {
	w.cancel()

	w.mu.Lock()
	defer w.mu.Unlock()

	var err error
	if w.notifyWatcher != nil {
		err = w.notifyWatcher.Close()
		w.notifyWatcher = nil
	}

	return err
}

// Watch updates the watched file paths.
func (w *Watcher) Watch(filePaths []string) {
	w.mu.Lock()
	defer w.mu.Unlock()

	fps := set.NewTreeSet(cmp.Compare[string])
	for _, fp := range filePaths {
		fps.Insert(fp)
	}
	w.filePaths = fps.Slice()

	dps := set.NewTreeSet(cmp.Compare[string])
	for _, fp := range filePaths {
		dps.Insert(filepath.Dir(fp))
	}
	w.directoryPaths = dps.Slice()

	w.checkLocked()
}

func (w *Watcher) handleNotifications() {
	if w.notifyWatcher == nil {
		return
	}

	for {
		select {
		case <-w.cancelCtx.Done():
			return
		case err := <-w.notifyWatcher.Errors:
			log.Debug().Err(err).Msg("fileutil/watcher: filesystem notification error")
		case evt := <-w.notifyWatcher.Events:
			if evt.Has(fsnotify.Create) || evt.Has(fsnotify.Remove) || evt.Has(fsnotify.Write) {
				w.mu.Lock()
				if wf, ok := w.files[evt.Name]; ok {
					wf.force = true
				}
				w.mu.Unlock()
			}
		}
	}
}

func (w *Watcher) handlePolling() {
	ticker := time.NewTicker(pollingInterval)
	defer ticker.Stop()

	for {
		w.mu.Lock()
		w.checkLocked()
		w.mu.Unlock()

		select {
		case <-w.cancelCtx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (w *Watcher) checkLocked() {
	w.checkDirectoriesLocked()
	if changedPaths := w.checkFilesLocked(); len(changedPaths) > 0 {
		log.Ctx(w.cancelCtx).Info().Strs("paths", changedPaths).Msg("fileutil/watcher: file change event")
		w.Signal.Broadcast(w.cancelCtx)
	}
}

func (w *Watcher) checkDirectoriesLocked() {
	// only watch directories that exist
	dirs := make([]string, 0, len(w.directoryPaths))
	for _, dp := range w.directoryPaths {
		fi, _ := os.Stat(dp)
		if fi != nil && fi.IsDir() {
			dirs = append(dirs, dp)
		}
	}

	updateMap(w.directories, dirs,
		func(dp string) struct{} {
			log.Ctx(w.cancelCtx).Debug().Str("path", dp).Msg("fileutil/watcher: watching directory")
			if w.notifyWatcher != nil {
				_ = w.notifyWatcher.Add(dp)
			}
			return struct{}{}
		},
		func(dp string, _ struct{}) {
			log.Ctx(w.cancelCtx).Debug().Str("path", dp).Msg("fileutil/watcher: stopped watching directory")
			if w.notifyWatcher != nil {
				_ = w.notifyWatcher.Remove(dp)
			}
		})
}

func (w *Watcher) checkFilesLocked() (changedPaths []string) {
	updateMap(w.files, w.filePaths,
		func(fp string) *watchedFile {
			log.Ctx(w.cancelCtx).Debug().Str("path", fp).Msg("fileutil/watcher: watching file")
			wf := newWatchedFile(fp)
			wf.check()
			return wf
		},
		func(fp string, _ *watchedFile) {
			log.Ctx(w.cancelCtx).Debug().Str("path", fp).Msg("fileutil/watcher: stopped watching file")
		})

	for fp, wf := range w.files {
		if wf.check() {
			changedPaths = append(changedPaths, fp)
		}
	}

	return changedPaths
}

func getFileSize(fi fs.FileInfo) int64 {
	if fi == nil {
		return 0
	}
	return fi.Size()
}

func getFileModTime(fi fs.FileInfo) int64 {
	if fi == nil {
		return 0
	}
	tm := fi.ModTime()
	// UnixNano on a zero time is undefined, so just always return 0 for that
	if tm.IsZero() {
		return 0
	}
	return tm.UnixNano()
}

func hashFile(path string) uint64 {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}

	h := xxh3.New()
	_, err = io.Copy(h, f)
	if err != nil {
		_ = f.Close()
		return 0
	}

	err = f.Close()
	if err != nil {
		return 0
	}

	return h.Sum64()
}

func swap[T comparable](dst *T, src T) (changed bool) {
	if *dst == src {
		return false
	}
	*dst = src
	return true
}

func updateMap[TKey comparable, T any](
	dst map[TKey]T,
	keys []TKey,
	create func(k TKey) T,
	remove func(k TKey, v T),
) {
	for _, k := range keys {
		if _, ok := dst[k]; !ok {
			dst[k] = create(k)
		}
	}
	s := set.From(keys)
	for k, v := range dst {
		if !s.Contains(k) {
			remove(k, v)
			delete(dst, k)
		}
	}
}
