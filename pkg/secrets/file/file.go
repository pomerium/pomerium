// Package file implements the file:// secret provider. It reads secret
// payloads from the local filesystem and polls their stat identity to push
// change hints so rotated files (including Kubernetes projected-volume
// symlink swaps) become visible promptly.
package file

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/zeebo/xxh3"
	"golang.org/x/sync/singleflight"

	"github.com/pomerium/pomerium/pkg/secrets/provider"
	"github.com/pomerium/pomerium/pkg/secrets/ref"
)

// Scheme is the URL scheme this provider handles.
const Scheme = "file"

// MaxFileSize is the largest payload Fetch will return. Larger files fail with
// provider.ErrTooLarge rather than being truncated. 1 MiB comfortably covers
// the largest plausible secret payloads (CA bundles, kubeconfigs, JSON service
// account keys) while keeping a misdirected ref (a device node, a FIFO, a log
// file) from growing the process without bound.
const MaxFileSize = 1 << 20

// DefaultPollInterval is how often each watched path is stat'ed for changes.
// It bounds rotation latency; a coarser interval costs nothing but promptness.
const DefaultPollInterval = 500 * time.Millisecond

// Provider is the file:// secret provider.
//
// Each watched path gets its own poller goroutine that stats the file (it
// never opens it) and notifies only that path's registrations when size,
// mtime, or inode change. Content identity comes from Fetch's Version, so the
// watcher is purely a change hint. Pollers are independent: a path on a hung
// mount stalls only its own registrations. The poller for a path exits when
// its last registration stops, so a Provider used only for validation never
// spawns goroutines.
type Provider struct {
	pollInterval time.Duration // zero means DefaultPollInterval

	// reads dedupes in-flight reads by path. On a hung mount a cancelled Fetch
	// abandons its reader goroutine (and its fd) with no way to interrupt it,
	// so without dedupe a resolver retry loop would park one more on every
	// attempt for the life of the process. Joining the in-flight read caps
	// that at one per path.
	reads singleflight.Group

	mu      sync.Mutex
	pollers map[string]*poller // watched path -> its poller and registrations
	nextID  int
}

type poller struct {
	cancel context.CancelFunc
	regs   map[int]*watchReg
}

type watchReg struct {
	notify  func()
	stopped atomic.Bool // set by unregister before the registration is dropped
}

// New returns a file Provider. The zero value is also usable.
func New() *Provider {
	return &Provider{}
}

var (
	_ provider.Provider = (*Provider)(nil)
	_ provider.Watcher  = (*Provider)(nil)
)

// Scheme implements provider.Provider.
func (*Provider) Scheme() string { return Scheme }

// Validate implements provider.Provider. The v1 file provider accepts no query
// parameters; a fragment (payload selector) is applied by the resolver, not
// here. Host and absolute-path shape are enforced by ref.Parse for this scheme.
func (*Provider) Validate(r ref.Ref) error {
	if r.Scheme() != Scheme {
		return fmt.Errorf("file secret: unexpected scheme %q", r.Scheme())
	}
	if q := r.URL().Query(); len(q) > 0 {
		return fmt.Errorf("file secret: unsupported query parameters: %v", slices.Sorted(maps.Keys(q)))
	}
	return nil
}

// Fetch implements provider.Provider. It re-validates the ref (nothing in the
// type system ties a ref to a completed Validate, so a ref config validation
// would reject must not be served off the disk), reads the file (at most
// MaxFileSize bytes), strips exactly one trailing newline (D1), and derives an
// opaque content-hash Version. A missing file, a path through a non-directory
// and a ref naming a directory are all not-found (negative-cacheable), an
// oversized file is provider.ErrTooLarge; any other read error is transient.
//
// Secrets are commonly mounted from a network or FUSE filesystem (CSI drivers,
// NFS), where open/read can block indefinitely and file I/O offers no
// cancellation, so the read runs detached from ctx.
func (p *Provider) Fetch(ctx context.Context, r ref.Ref) (provider.Result, error) {
	if err := p.Validate(r); err != nil {
		return provider.Result{}, err
	}
	path := r.URL().Path

	data, err := p.read(ctx, path)
	if err != nil {
		return provider.Result{}, fmt.Errorf("file secret %q: %w", path, err)
	}

	data = trimOneTrailingNewline(data)
	version := strconv.FormatUint(xxh3.Hash(data), 16)
	return provider.Result{Value: data, Version: version}, nil
}

// read returns path's contents, joining any read of the same path already in
// flight. Like detach it abandons the read rather than waiting when ctx is
// done, and refuses an already-done ctx without touching the filesystem.
func (p *Provider) read(ctx context.Context, path string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ch := p.reads.DoChan(path, func() (any, error) { return readCapped(path) })
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-ch:
		if res.Err != nil {
			return nil, res.Err
		}
		data, _ := res.Val.([]byte)
		if res.Shared {
			// Several Fetches share one read: hand each its own buffer so a
			// caller that writes through Result.Value cannot corrupt another's
			// secret.
			data = bytes.Clone(data)
		}
		return data, nil
	}
}

// readCapped reads up to MaxFileSize+1 bytes; a full extra byte means the file
// is over the cap and is rejected with provider.ErrTooLarge instead of being
// silently truncated. The cap applies to the on-disk size, before
// trailing-newline trimming. Errors come back already classified for the
// resolver.
func readCapped(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		// ENOENT and ENOTDIR (a path component that is not a directory) both
		// say the ref cannot resolve until the config or the mount changes, so
		// both are negative-cacheable rather than retried with backoff.
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) {
			return nil, provider.ErrNotFound
		}
		return nil, err
	}
	defer f.Close()

	// A directory opens successfully and only fails on read, with an error that
	// varies by platform. Reject it here: a ref naming a directory is the same
	// permanent misconfiguration as a missing file.
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if fi.IsDir() {
		return nil, fmt.Errorf("is a directory: %w", provider.ErrNotFound)
	}

	data, err := io.ReadAll(io.LimitReader(f, MaxFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxFileSize {
		return nil, fmt.Errorf("exceeds %d bytes: %w", MaxFileSize, provider.ErrTooLarge)
	}
	return data, nil
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

// detach runs fn on its own goroutine and returns its result, or ctx.Err() if
// ctx is done first, leaving fn (blocked on a hung mount, say) to finish on its
// own with its result discarded. An already-done ctx never runs fn at all:
// select picks randomly among ready cases, so without the up-front check a
// cancelled call could still start a filesystem operation that never returns.
func detach[T any](ctx context.Context, fn func() T) (T, error) {
	var zero T
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	ch := make(chan T, 1)
	go func() { ch <- fn() }()
	select {
	case <-ctx.Done():
		return zero, ctx.Err()
	case v := <-ch:
		return v, nil
	}
}

// Watch implements provider.Watcher. Watching stops when the returned stop
// func is called or ctx is done, whichever comes first. No new delivery begins
// after stop returns; a delivery already in progress completes.
//
// The baseline stat runs before registration so a change racing Watch is not
// missed. Like Fetch's read it is detached from ctx, and an already-done ctx is
// an error rather than a dead registration.
func (p *Provider) Watch(ctx context.Context, r ref.Ref, notify func()) (func(), error) {
	if err := p.Validate(r); err != nil {
		return nil, err
	}
	path := r.URL().Path

	baseline, err := detach(ctx, func() fileState { return statFile(path) })
	if err != nil {
		return nil, fmt.Errorf("file secret %q: %w", path, err)
	}

	id := p.register(path, notify, baseline)
	teardown := func() { p.unregister(path, id) }
	cancelAfter := context.AfterFunc(ctx, teardown)
	return func() {
		cancelAfter()
		teardown()
	}, nil
}

// register adds a registration under path, starting the path's poller from
// baseline if it is the first. It returns the registration id.
func (p *Provider) register(path string, notify func(), baseline fileState) int {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.pollers == nil {
		p.pollers = make(map[string]*poller)
	}
	pl := p.pollers[path]
	if pl == nil {
		ctx, cancel := context.WithCancel(context.Background())
		pl = &poller{cancel: cancel, regs: make(map[int]*watchReg)}
		p.pollers[path] = pl
		go p.poll(ctx, path, baseline)
	}

	id := p.nextID
	p.nextID++
	pl.regs[id] = &watchReg{notify: notify}
	return id
}

// unregister drops a registration, stopping the path's poller when it was the
// last one. The poller is cancelled, not joined: it may be inside a stat that
// a hung mount never returns from. Unknown ids are ignored, so a stop func may
// be called more than once.
func (p *Provider) unregister(path string, id int) {
	p.mu.Lock()
	defer p.mu.Unlock()

	pl := p.pollers[path]
	if pl == nil {
		return
	}
	reg, ok := pl.regs[id]
	if !ok {
		return
	}
	reg.stopped.Store(true)
	delete(pl.regs, id)
	if len(pl.regs) == 0 {
		pl.cancel()
		delete(p.pollers, path)
	}
}

// poll stats path every poll interval and notifies the path's registrations
// on any change from the previous observation.
func (p *Provider) poll(ctx context.Context, path string, prev fileState) {
	interval := p.pollInterval
	if interval == 0 {
		interval = DefaultPollInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		cur := statFile(path)
		if cur == prev {
			continue
		}
		prev = cur
		p.notifyPath(path)
	}
}

// notifyPath invokes every live registration on path. Callbacks run outside
// the lock so they may call Watch or a stop func; the stopped flag is checked
// immediately before each call so a registration stopped by an earlier
// callback in the same round is skipped.
func (p *Provider) notifyPath(path string) {
	p.mu.Lock()
	var regs []*watchReg
	if pl := p.pollers[path]; pl != nil {
		regs = slices.Collect(maps.Values(pl.regs))
	}
	p.mu.Unlock()

	for _, reg := range regs {
		if !reg.stopped.Load() {
			reg.notify()
		}
	}
}

// fileState is the stat-derived identity of a watched path. Two equal states
// mean "probably unchanged"; any difference is a change hint. Symlinks are
// followed, so a Kubernetes projected-volume swap shows up as a new inode.
type fileState struct {
	exists  bool
	size    int64
	modTime int64
	mode    fs.FileMode
	ino     uint64
}

// statFile never opens the file. A path that cannot be stat'ed (missing, or a
// component that is not a directory) is the zero state.
func statFile(path string) fileState {
	fi, err := os.Stat(path)
	if err != nil {
		return fileState{}
	}
	st := fileState{exists: true, size: fi.Size(), modTime: fi.ModTime().UnixNano(), mode: fi.Mode()}
	if sys, ok := fi.Sys().(*syscall.Stat_t); ok {
		st.ino = sys.Ino
	}
	return st
}
