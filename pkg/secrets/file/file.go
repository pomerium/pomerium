// Package file implements the file:// secret provider. It reads secret
// payloads from the local filesystem and, via internal/fileutil.Watcher,
// pushes change hints so rotated files (including Kubernetes projected-volume
// symlink swaps) become visible promptly.
package file

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"strconv"
	"sync"

	"github.com/zeebo/xxh3"

	"github.com/pomerium/pomerium/internal/fileutil"
	"github.com/pomerium/pomerium/pkg/secrets/provider"
	"github.com/pomerium/pomerium/pkg/secrets/ref"
)

// Scheme is the URL scheme this provider handles.
const Scheme = "file"

// Provider is the file:// secret provider.
//
// A single fileutil.Watcher (lazily created on first Watch) backs all watch
// registrations. Because the watcher signals on any change to any watched
// path without saying which, every change notifies all registered refs; the
// resolver de-noises via each fetch's Version. The watcher is torn down when
// the last registration stops, so a Provider used only for validation never
// spawns goroutines.
type Provider struct {
	mu          sync.Mutex
	watcher     *fileutil.Watcher
	drainCancel context.CancelFunc
	watches     map[int]watchReg // registration id -> reg
	pathRefs    map[string]int   // watched path -> refcount (the union)
	nextID      int
}

type watchReg struct {
	path   string
	notify func()
}

// New returns a file Provider.
func New() *Provider {
	return &Provider{
		watches:  make(map[int]watchReg),
		pathRefs: make(map[string]int),
	}
}

var (
	_ provider.Provider = (*Provider)(nil)
	_ provider.Watcher  = (*Provider)(nil)
)

// Scheme implements provider.Provider.
func (*Provider) Scheme() string { return Scheme }

// Validate implements provider.Provider. The v1 file provider accepts no query
// parameters; a fragment (payload selector) is applied by the resolver, not
// here. Host and absolute-path shape are already enforced by ref.Parse.
func (*Provider) Validate(r ref.Ref) error {
	u := r.URL()
	if u.Host != "" {
		return fmt.Errorf("file secret: URL must not have a host component (got %q)", u.Host)
	}
	if len(u.Path) == 0 || u.Path[0] != '/' {
		return errors.New("file secret: path must be absolute")
	}
	if q := u.Query(); len(q) > 0 {
		keys := make([]string, 0, len(q))
		for k := range q {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		return fmt.Errorf("file secret: unsupported query parameters: %v", keys)
	}
	return nil
}

// Fetch implements provider.Provider. It reads the file, strips exactly one
// trailing newline (D1), and derives an opaque content-hash Version. A missing
// file is not-found (negative-cacheable); any other read error is transient.
func (*Provider) Fetch(_ context.Context, r ref.Ref) (provider.Result, error) {
	path := r.URL().Path

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return provider.Result{}, fmt.Errorf("file secret %q: %w", path, provider.ErrNotFound)
		}
		return provider.Result{}, fmt.Errorf("file secret %q: %w", path, err)
	}

	data = trimOneTrailingNewline(data)
	version := strconv.FormatUint(xxh3.Hash(data), 16)
	return provider.Result{Value: data, TTL: 0, Version: version}, nil
}

// trimOneTrailingNewline strips a single trailing "\n" or "\r\n"; everything
// else is byte-exact (D1).
func trimOneTrailingNewline(b []byte) []byte {
	n := len(b)
	if n == 0 || b[n-1] != '\n' {
		return b
	}
	if n >= 2 && b[n-2] == '\r' {
		return b[:n-2]
	}
	return b[:n-1]
}

// Watch implements provider.Watcher. Watching stops when the returned stop func
// is called or ctx is done, whichever comes first.
func (p *Provider) Watch(ctx context.Context, r ref.Ref, notify func()) (func(), error) {
	path := r.URL().Path

	p.mu.Lock()
	if p.watcher == nil {
		p.watcher = fileutil.NewWatcher()
		signalCh := p.watcher.Bind()
		var drainCtx context.Context
		drainCtx, p.drainCancel = context.WithCancel(context.Background())
		go p.drain(drainCtx, signalCh)
	}
	id := p.nextID
	p.nextID++
	p.watches[id] = watchReg{path: path, notify: notify}
	p.pathRefs[path]++
	p.rebuildPathsLocked()
	p.mu.Unlock()

	var once sync.Once
	teardown := func() {
		once.Do(func() { p.unregister(id) })
	}
	cancelAfter := context.AfterFunc(ctx, teardown)
	return func() {
		cancelAfter()
		teardown()
	}, nil
}

func (p *Provider) unregister(id int) {
	p.mu.Lock()
	reg, ok := p.watches[id]
	if !ok {
		p.mu.Unlock()
		return
	}
	delete(p.watches, id)
	p.pathRefs[reg.path]--
	if p.pathRefs[reg.path] <= 0 {
		delete(p.pathRefs, reg.path)
	}

	var toClose *fileutil.Watcher
	if len(p.watches) == 0 {
		p.drainCancel()
		p.drainCancel = nil
		toClose = p.watcher
		p.watcher = nil
	} else {
		p.rebuildPathsLocked()
	}
	p.mu.Unlock()

	if toClose != nil {
		_ = toClose.Close()
	}
}

// rebuildPathsLocked re-points the watcher at the current union of paths.
func (p *Provider) rebuildPathsLocked() {
	paths := make([]string, 0, len(p.pathRefs))
	for path := range p.pathRefs {
		paths = append(paths, path)
	}
	p.watcher.Watch(paths)
}

// drain forwards each change signal to all currently-registered refs.
func (p *Provider) drain(ctx context.Context, signalCh chan context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-signalCh:
			p.notifyAll()
		}
	}
}

func (p *Provider) notifyAll() {
	p.mu.Lock()
	notifies := make([]func(), 0, len(p.watches))
	for _, reg := range p.watches {
		notifies = append(notifies, reg.notify)
	}
	p.mu.Unlock()

	for _, notify := range notifies {
		notify()
	}
}
