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

	"github.com/pomerium/pomerium/internal/log"
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

// MaxParkedReads is how many abandoned reads of one path may stay parked in an
// uninterruptible syscall before further fetches of that path are refused
// with ErrReadBlocked. It bounds the goroutines and descriptors a wedged mount
// can pin per path while still letting a later read reach a path that has
// been remounted underneath the stuck ones.
const MaxParkedReads = 3

// DefaultParkedRetryInterval is the minimum time between starting reads of a
// path while an earlier read of it is parked, so retries against a wedged
// mount reach MaxParkedReads slowly rather than in one burst.
const DefaultParkedRetryInterval = 5 * time.Second

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

	// parkedRetryInterval spaces new reads of a path that already has a read
	// parked; zero means DefaultParkedRetryInterval.
	parkedRetryInterval time.Duration

	// readFile is the read strategy, swappable so tests can stand in for a
	// wedged mount; nil means readCapped.
	readFile func(path string) ([]byte, error)

	mu      sync.Mutex
	pollers map[string]*poller    // watched path -> its poller and registrations
	reads   map[string]*pathReads // path -> its live and parked reads
	nextID  int
}

// pathReads tracks the reads of one path: at most one live read that current
// callers share, plus the reads abandoned by callers that gave up and now
// parked in an uninterruptible syscall.
type pathReads struct {
	live      *readCall
	parked    int
	lastStart time.Time
}

// readCall is one read of a path. waiters counts the live callers still
// interested; when it drops to zero before the read finishes, the read is
// abandoned and moves from live to parked.
type readCall struct {
	done     chan struct{}
	started  time.Time
	waiters  int
	finished bool // set under Provider.mu once the read has returned
	parked   bool // set under Provider.mu when the last waiter abandons it
	data     []byte
	err      error
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

// ErrReadBlocked reports that earlier reads of this path are still parked in
// an uninterruptible syscall, so the fetch was refused rather than piling
// another blocked reader on top of them. It is transient: a later fetch
// proceeds once a parked read returns or the retry interval has passed.
var ErrReadBlocked = errors.New("an earlier read of this file is still blocked")

// Fetch implements provider.Provider. It re-validates the ref (nothing in the
// type system ties a ref to a completed Validate, so a ref config validation
// would reject must not be served off the disk), reads the file (at most
// MaxFileSize bytes), strips exactly one trailing newline (D1), and derives an
// opaque content-hash Version. A missing file, a path through a non-directory
// and a ref that does not name a regular file are all not-found
// (negative-cacheable), an oversized file is provider.ErrTooLarge; any other
// read error is transient.
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

// read returns path's contents, honouring ctx even though the read itself
// cannot be interrupted: a regular file on a wedged NFS or FUSE mount blocks
// in open(2) or read(2) with no cancellation, so the read runs on its own
// goroutine and is abandoned rather than waited on.
//
// Abandoning is bounded, which is what makes it safe:
//
//   - Concurrent live callers share one read, so a fan-out over one path costs
//     one descriptor, not one per binding.
//   - Once the last caller gives up, the read is abandoned and parked. A later
//     fetch never joins it — stale work must never answer for a fresh
//     request, the failure Go's net resolver added singleflight.ForgetUnshared
//     to avoid (golang/go#22724).
//   - A later fetch may start a fresh read alongside the parked ones, but only
//     every parkedRetryInterval and only while fewer than MaxParkedReads are
//     parked; otherwise it fails fast with ErrReadBlocked. Retrying against a
//     wedged mount therefore pins a fixed number of goroutines and descriptors
//     per path rather than one per attempt, the unbounded growth that
//     exhausted csi-driver-nfs (#1271).
//
// Allowing a fresh read at all matters because a parked read is stuck on the
// mount it started on, not on the path: the standard recovery for a stale NFS
// mount is a lazy unmount and remount, after which the path is healthy while
// the old read may never return.
func (p *Provider) read(ctx context.Context, path string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	p.mu.Lock()
	if p.reads == nil {
		p.reads = make(map[string]*pathReads)
	}
	pr := p.reads[path]
	if pr == nil {
		pr = &pathReads{}
		p.reads[path] = pr
	}
	c := pr.live
	if c != nil {
		c.waiters++
	} else {
		now := time.Now()
		if pr.parked > 0 {
			if pr.parked >= MaxParkedReads || now.Sub(pr.lastStart) < p.retryInterval() {
				p.mu.Unlock()
				return nil, ErrReadBlocked
			}
			log.Ctx(ctx).Warn().Str("path", path).Int("parked", pr.parked).
				Msg("file secret: earlier reads are still blocked; retrying with a fresh read")
		}
		c = &readCall{done: make(chan struct{}), started: now, waiters: 1}
		pr.live, pr.lastStart = c, now
		go p.runRead(context.WithoutCancel(ctx), path, pr, c)
	}
	p.mu.Unlock()

	select {
	case <-ctx.Done():
		p.drop(ctx, path, pr, c)
		return nil, ctx.Err()
	case <-c.done:
		p.drop(ctx, path, pr, c)
		if c.err != nil {
			return nil, c.err
		}
		// One read can answer several callers, so each gets its own buffer: a
		// caller that writes through Result.Value must not reach another's
		// secret.
		return bytes.Clone(c.data), nil
	}
}

func (p *Provider) retryInterval() time.Duration {
	if p.parkedRetryInterval == 0 {
		return DefaultParkedRetryInterval
	}
	return p.parkedRetryInterval
}

// drop releases one caller's interest in c. The last caller to give up on an
// unfinished read parks it, so the next fetch starts fresh instead of joining.
func (p *Provider) drop(ctx context.Context, path string, pr *pathReads, c *readCall) {
	p.mu.Lock()
	defer p.mu.Unlock()

	c.waiters--
	if c.waiters > 0 || c.finished {
		return
	}
	c.parked = true
	pr.live = nil
	pr.parked++
	ev := log.Ctx(ctx).Warn()
	if pr.parked >= MaxParkedReads {
		ev = log.Ctx(ctx).Error()
	}
	ev.Str("path", path).
		Dur("elapsed", time.Since(c.started)).
		Int("parked", pr.parked).
		Int("max-parked", MaxParkedReads).
		Msg("file secret: read abandoned while blocked in the filesystem (wedged mount?); it stays parked until the kernel returns it")
}

// runRead performs the read and retires it. The call is unlinked from the path
// before done is closed so that a fetch arriving in between starts a fresh
// read rather than joining a finished one.
func (p *Provider) runRead(ctx context.Context, path string, pr *pathReads, c *readCall) {
	read := p.readFile
	if read == nil {
		read = readCapped
	}
	data, err := read(path)

	p.mu.Lock()
	c.data, c.err, c.finished = data, err, true
	if pr.live == c {
		pr.live = nil
	}
	if c.parked {
		pr.parked--
		log.Ctx(ctx).Info().Str("path", path).
			Dur("elapsed", time.Since(c.started)).
			Int("parked", pr.parked).
			Msg("file secret: parked read returned")
	}
	if pr.live == nil && pr.parked == 0 && p.reads[path] == pr {
		delete(p.reads, path)
	}
	p.mu.Unlock()

	close(c.done)
}

// readCapped reads up to MaxFileSize+1 bytes; a full extra byte means the file
// is over the cap and is rejected with provider.ErrTooLarge instead of being
// silently truncated. The cap applies to the on-disk size, before
// trailing-newline trimming. Errors come back already classified for the
// resolver.
//
// The open is non-blocking and the file type is checked before any read, so a
// ref pointing at a FIFO, device or socket fails fast instead of parking a
// goroutine in open(2) forever: opening a FIFO with no writer blocks
// indefinitely without O_NONBLOCK. This is the only hang class we can rule
// out in process — a regular file on a wedged NFS or FUSE mount still blocks,
// which is why Fetch detaches the read.
func readCapped(path string) ([]byte, error) {
	// O_NONBLOCK affects the open of a special file only; for a regular file
	// it is a no-op, and symlinks (a Kubernetes projected volume reaches its
	// payload through two of them) are still followed.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
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

	// Stat the descriptor, never the path: os.Lstat would see the symlink a
	// projected volume mounts and reject every Kubernetes secret. A directory
	// opens successfully and only fails on read, with a platform-dependent
	// error, and a device or FIFO would read without ever ending. A secret is
	// a regular file; anything else is a permanent misconfiguration, so it is
	// classified alongside a missing file.
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("not a regular file (%s): %w", fi.Mode().Type(), provider.ErrNotFound)
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
