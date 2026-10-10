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
// with ErrReadBlocked until one of them returns. Each parked read pins a
// goroutine, the OS thread its syscall blocks and a descriptor, and the Go
// runtime aborts the process past its thread limit, so a wedged mount must
// cost a fixed number of them per path; see Provider.read.
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
	// Configuration, set before first use and read without a lock.
	pollInterval time.Duration // zero means DefaultPollInterval

	// parkedRetryInterval spaces new reads of a path that already has a read
	// parked; zero means DefaultParkedRetryInterval. Only goroutines calling
	// Fetch read it, so tests also change it between fetches.
	parkedRetryInterval time.Duration

	// readFile is the read strategy, swappable so tests can stand in for a
	// wedged mount; nil means readCapped.
	readFile func(path string) ([]byte, error)

	reads readGroup // the fetch state of every path, under its own lock

	// watchMu guards pollers, nextID and each poller's regs.
	watchMu sync.Mutex
	pollers map[string]*poller // watched path -> its poller and registrations
	nextID  int
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
// proceeds once a parked read returns or, below MaxParkedReads, once the retry
// interval has passed.
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
//     one descriptor, not one per caller.
//   - Once the last caller gives up, the read is abandoned and parked. A later
//     fetch never joins it — stale work must never answer for a fresh
//     request.
//   - A later fetch may start a fresh read alongside the parked ones, but only
//     every parkedRetryInterval and only while fewer than MaxParkedReads are
//     parked; otherwise it fails fast with ErrReadBlocked. Retrying against a
//     wedged mount therefore pins a fixed number of goroutines, threads and
//     descriptors per path rather than one per attempt.
//
// At the cap the path stays refused until a parked read returns, which on a
// hard NFS mount is when the server answers again. Reads that never return,
// as on a mount lazily unmounted and replaced, keep it refused until restart.
func (p *Provider) read(ctx context.Context, path string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	c, fresh, err := p.reads.admit(ctx, path, p.retryInterval())
	if err != nil {
		return nil, err
	}
	if fresh {
		go p.runRead(context.WithoutCancel(ctx), c)
	}
	return p.await(ctx, c)
}

// await waits for c within ctx; a caller that gives up releases its interest
// in c.
func (p *Provider) await(ctx context.Context, c *readCall) ([]byte, error) {
	select {
	case <-ctx.Done():
		p.reads.abandon(ctx, c)
		return nil, ctx.Err()
	case <-c.done:
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

// runRead performs c's read and publishes its result.
func (p *Provider) runRead(ctx context.Context, c *readCall) {
	read := p.readFile
	if read == nil {
		read = readCapped
	}
	data, err := read(c.owner.path)
	p.reads.finishRead(ctx, c, data, err)
}

// A readGroup holds the fetch state of every path. Fetching is split in three
// layers, so which code runs under mu is plain from where it lives:
//
//   - Provider's fetch methods (read, await, runRead) never hold mu. They are
//     the only code that waits: on ctx, on a read, or on the filesystem.
//   - readGroup's methods take mu for their whole call. Outside tests, they
//     are the only code that does.
//   - pathReads' methods are the state transitions, always called with mu
//     held.
//
// Code under mu never waits on the filesystem or on another goroutine, but
// the transitions do log, so a log writer that blocks stalls fetches. The
// clock is read under mu as well, so the times the transitions see are ordered
// the way the transitions are.
//
// mu guards paths, every pathReads in it, and the fields of readCall marked as
// guarded. Between readGroup calls, paths holds exactly the pathReads that are
// not idle. A read is recorded in its pathReads from admission until it is
// published, so a recorded read's owner is always the pathReads in paths for
// its path.
type readGroup struct {
	mu    sync.Mutex
	paths map[string]*pathReads
}

// admit admits a fetch of path; see pathReads.admit.
func (g *readGroup) admit(ctx context.Context, path string, retry time.Duration) (*readCall, bool, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.paths == nil {
		g.paths = make(map[string]*pathReads)
	}
	pr := g.paths[path]
	if pr == nil {
		pr = &pathReads{path: path, parked: make(map[*readCall]struct{})}
		g.paths[path] = pr
	}
	return pr.admit(ctx, time.Now(), retry)
}

// abandon releases one caller's interest in c; see pathReads.abandon. It
// leaves paths alone: a read still running stays recorded, live or parked, and
// for a finished read, whose owner may already have been retired, abandon
// changes nothing but c.waiters.
func (g *readGroup) abandon(ctx context.Context, c *readCall) {
	g.mu.Lock()
	defer g.mu.Unlock()

	c.owner.abandon(ctx, c, time.Now())
}

// finishRead publishes c's result and retires its owner if that leaves it
// idle; see pathReads.finishRead.
func (g *readGroup) finishRead(ctx context.Context, c *readCall, data []byte, err error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	pr := c.owner
	pr.finishRead(ctx, c, data, err, time.Now())
	if pr.idle() {
		delete(g.paths, pr.path)
	}
}

// readCall is one read of a path.
type readCall struct {
	// Set at creation and never changed.
	owner   *pathReads
	done    chan struct{} // closed, under readGroup.mu, once the read has returned
	started time.Time

	// Guarded by readGroup.mu.
	waiters  int  // live callers still interested; the last to give up parks the read
	finished bool // the read has returned and done is closed

	// Written under readGroup.mu before done is closed, and read without it
	// only after.
	data []byte
	err  error
}

// pathReads is the state of one path's reads: at most one live read that
// current callers share, and the reads abandoned by callers that gave up and
// now parked in an uninterruptible syscall. path is set at creation and read
// without the lock; every other field is guarded by readGroup.mu. Its methods
// are the path's state transitions and are only called with mu held.
type pathReads struct {
	path      string
	live      *readCall
	parked    map[*readCall]struct{}
	lastStart time.Time
}

// admit decides how a fetch proceeds and reports the read it waits on and
// whether that read is fresh. It joins the live read if there is one;
// otherwise it records a fresh read, unless the parked-read bounds described
// on Provider.read refuse it with ErrReadBlocked. A fresh read is recorded but
// not yet running; the caller starts it.
func (pr *pathReads) admit(ctx context.Context, now time.Time, retry time.Duration) (*readCall, bool, error) {
	if c := pr.live; c != nil {
		c.waiters++
		return c, false, nil
	}
	if n := len(pr.parked); n > 0 {
		if n >= MaxParkedReads || now.Sub(pr.lastStart) < retry {
			return nil, false, ErrReadBlocked
		}
		log.Ctx(ctx).Debug().Str("path", pr.path).Int("parked", n).
			Msg("file secret: earlier reads are still blocked; retrying with a fresh read")
	}
	c := &readCall{owner: pr, done: make(chan struct{}), started: now, waiters: 1}
	pr.live, pr.lastStart = c, now
	return c, true, nil
}

// abandon releases one caller's interest in c. The last caller to give up on
// an unfinished read parks it, so the next fetch starts fresh instead of
// joining.
func (pr *pathReads) abandon(ctx context.Context, c *readCall, now time.Time) {
	c.waiters--
	if c.waiters > 0 || c.finished {
		return
	}
	pr.live = nil
	pr.parked[c] = struct{}{}
	n := len(pr.parked)
	ev := log.Ctx(ctx).Info()
	if n >= MaxParkedReads {
		ev = log.Ctx(ctx).Error()
	}
	ev.Str("path", pr.path).
		Dur("elapsed", now.Sub(c.started)).
		Int("parked", n).
		Int("max-parked", MaxParkedReads).
		Msg("file secret: read abandoned while blocked in the filesystem (wedged mount?); it stays parked until the kernel returns it")
}

// finishRead publishes c's result: it records it, unlinks c so that a later
// fetch starts a fresh read rather than joining a finished one, and closes
// c.done.
func (pr *pathReads) finishRead(ctx context.Context, c *readCall, data []byte, err error, now time.Time) {
	c.data, c.err, c.finished = data, err, true
	if pr.live == c {
		pr.live = nil
	}
	if _, parked := pr.parked[c]; parked {
		delete(pr.parked, c)
		log.Ctx(ctx).Info().Str("path", pr.path).
			Dur("elapsed", now.Sub(c.started)).
			Int("parked", len(pr.parked)).
			Msg("file secret: parked read returned")
	}
	close(c.done)
}

// idle reports whether pr holds nothing worth keeping.
func (pr *pathReads) idle() bool {
	return pr.live == nil && len(pr.parked) == 0
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

type poller struct {
	cancel context.CancelFunc // set at creation
	regs   map[int]*watchReg  // guarded by Provider.watchMu
}

type watchReg struct {
	notify  func()
	stopped atomic.Bool // set by unregister before the registration is dropped
}

// register adds a registration under path, starting the path's poller from
// baseline if it is the first. It returns the registration id.
func (p *Provider) register(path string, notify func(), baseline fileState) int {
	p.watchMu.Lock()
	defer p.watchMu.Unlock()

	if p.pollers == nil {
		p.pollers = make(map[string]*poller)
	}
	pl := p.pollers[path]
	if pl == nil {
		ctx, cancel := context.WithCancel(context.Background())
		pl = &poller{cancel: cancel, regs: make(map[int]*watchReg)}
		p.pollers[path] = pl
		go p.poll(ctx, pl, path, baseline)
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
	p.watchMu.Lock()
	defer p.watchMu.Unlock()

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

// poll stats path every poll interval and notifies pl's registrations on any
// change from the previous observation.
func (p *Provider) poll(ctx context.Context, pl *poller, path string, prev fileState) {
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
		p.notify(pl)
	}
}

// notify invokes every live registration of pl. It resolves pl, not its path,
// so a poller cancelled mid-stat reaches only its own (by then empty)
// registrations, never a successor's. Callbacks run outside the lock so they
// may call Watch or a stop func; the stopped flag is checked immediately
// before each call so a registration stopped by an earlier callback in the
// same round is skipped.
func (p *Provider) notify(pl *poller) {
	for _, reg := range p.registrations(pl) {
		if !reg.stopped.Load() {
			reg.notify()
		}
	}
}

// registrations returns a snapshot of pl's registrations.
func (p *Provider) registrations(pl *poller) []*watchReg {
	p.watchMu.Lock()
	defer p.watchMu.Unlock()

	return slices.Collect(maps.Values(pl.regs))
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
