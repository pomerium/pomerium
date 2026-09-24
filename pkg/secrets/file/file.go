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
// can pin per path. Past the cap, a fresh read is admitted only once a stat
// probe shows the path now resolves to a different device than every parked
// read, which is what a remount looks like; see Provider.read.
const MaxParkedReads = 3

// MaxParkedProbes is how many remount probes of one path may stay parked. A
// probe is a stat: it holds a goroutine but no descriptor. One stuck on the old
// mount is replaced after a backoff, so a probe started before a remount does
// not keep a later one from reaching the new mount.
const MaxParkedProbes = 16

// DefaultParkedRetryInterval is the minimum time between starting reads of a
// path while an earlier read of it is parked, so retries against a wedged
// mount reach MaxParkedReads slowly rather than in one burst. It is also the
// first remount-probe backoff, which doubles up to maxProbeBackoff.
const DefaultParkedRetryInterval = 5 * time.Second

const maxProbeBackoff = time.Hour

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

	// readFile and statPath are the read and remount-probe strategies,
	// swappable so tests can stand in for a wedged or remounted mount; nil
	// means readCapped and statFile.
	readFile func(path string, opened func(dev uint64)) ([]byte, error)
	statPath func(path string) fileState

	mu      sync.Mutex
	pollers map[string]*poller    // watched path -> its poller and registrations
	reads   map[string]*pathReads // path -> its live and parked reads
	nextID  int
}

// pathReads tracks the reads of one path: at most one live read that current
// callers share, the reads abandoned by callers that gave up and now parked in
// an uninterruptible syscall, and the remount probe that lets a fresh read past
// the parked cap. Its methods are the path's state transitions; they never
// block and must be called under Provider.mu.
type pathReads struct {
	path      string
	live      *readCall
	parked    map[*readCall]struct{}
	lastStart time.Time

	probe         *probeCall // the probe in flight, if any
	probesParked  int        // abandoned probes still stuck in stat
	probeBackoff  time.Duration
	lastProbeDone time.Time
	// admitDev is a device a probe found the path on that no parked read is
	// on; the next fetch at the cap may start one read against it.
	admitDev   uint64
	admitReady bool
}

// An admission is pathReads.admit's verdict for one fetch: exactly one of a
// read to wait on or a remount probe to wait on before asking again. A fresh
// read and a probe are recorded but not yet running; the caller starts them.
type admission struct {
	read  *readCall
	fresh bool
	probe *probeCall
}

// admit decides how a fetch proceeds. It joins the live read if there is one;
// otherwise, subject to the parked-read bounds described on Provider.read, it
// records a fresh read or, at the parked cap, a remount probe, or refuses with
// ErrReadBlocked. probed reports whether the fetch has already waited on a
// probe.
func (pr *pathReads) admit(ctx context.Context, now time.Time, retry time.Duration, probed bool) (admission, error) {
	if c := pr.live; c != nil {
		c.waiters++
		return admission{read: c}, nil
	}

	// An admission is for a device no parked read is on. A read that parked
	// since the probe (one started below the cap that then opened on the new
	// device, say) voids it.
	if pr.admitReady && pr.onParkedDevice(pr.admitDev) {
		pr.admitReady = false
	}

	var dev uint64
	var devKnown bool
	if n := len(pr.parked); n > 0 {
		switch {
		case n >= MaxParkedReads && pr.admitReady:
			dev, devKnown = pr.admitDev, true
			pr.admitReady = false
			log.Ctx(ctx).Warn().Str("path", pr.path).Int("parked", n).Uint64("dev", dev).
				Msg("file secret: path now resolves to a different device than its blocked reads (remounted?); retrying with a fresh read")
		case n >= MaxParkedReads:
			// A fetch that starts a probe waits for it, within ctx, so the
			// first fetch after a remount can already succeed. Others fail
			// fast rather than wait on a probe that may be as stuck as the
			// reads, and no fetch asks for a second verdict.
			var pc *probeCall
			if !probed {
				pc = pr.startProbe(ctx, now, retry)
			}
			if pc == nil {
				return admission{}, ErrReadBlocked
			}
			return admission{probe: pc}, nil
		case now.Sub(pr.lastStart) < retry:
			return admission{}, ErrReadBlocked
		default:
			log.Ctx(ctx).Warn().Str("path", pr.path).Int("parked", n).
				Msg("file secret: earlier reads are still blocked; retrying with a fresh read")
		}
	}
	c := &readCall{done: make(chan struct{}), started: now, waiters: 1, dev: dev, devKnown: devKnown}
	pr.live, pr.lastStart = c, now
	return admission{read: c, fresh: true}, nil
}

// abandon releases one caller's interest in c. The last caller to give up on
// an unfinished read parks it, so the next fetch starts fresh instead of
// joining.
func (pr *pathReads) abandon(ctx context.Context, c *readCall) {
	c.waiters--
	if c.waiters > 0 || c.finished {
		return
	}
	c.parked = true
	pr.live = nil
	pr.parked[c] = struct{}{}
	n := len(pr.parked)
	ev := log.Ctx(ctx).Warn()
	if n >= MaxParkedReads {
		ev = log.Ctx(ctx).Error()
	}
	ev.Str("path", pr.path).
		Dur("elapsed", time.Since(c.started)).
		Int("parked", n).
		Int("max-parked", MaxParkedReads).
		Msg("file secret: read abandoned while blocked in the filesystem (wedged mount?); it stays parked until the kernel returns it")
}

// finishRead records c's result and unlinks it, before c.done is closed, so
// that a fetch arriving in between starts a fresh read rather than joining a
// finished one.
func (pr *pathReads) finishRead(ctx context.Context, c *readCall, data []byte, err error) {
	c.data, c.err, c.finished = data, err, true
	if pr.live == c {
		pr.live = nil
	}
	if c.parked {
		delete(pr.parked, c)
		log.Ctx(ctx).Info().Str("path", pr.path).
			Dur("elapsed", time.Since(c.started)).
			Int("parked", len(pr.parked)).
			Msg("file secret: parked read returned")
		// An admission only matters while reads are parked, so it lapses
		// with them.
		if len(pr.parked) == 0 {
			pr.admitReady = false
		}
	}
}

// startProbe records a new remount probe of a path at the parked cap and
// returns it, or returns nil when none is due: one is already in flight, or the
// last finished less than a retry interval ago. A probe in flight longer than
// the current backoff is presumed stuck on the old mount and replaced, with
// the backoff doubling, so one that started before a remount cannot keep a
// later one from reaching the new mount. At most MaxParkedProbes may be stuck
// at once.
func (pr *pathReads) startProbe(ctx context.Context, now time.Time, retry time.Duration) *probeCall {
	if pr.probeBackoff == 0 {
		pr.probeBackoff = retry
	}
	if pc := pr.probe; pc != nil {
		if now.Sub(pc.started) < pr.probeBackoff || pr.probesParked+1 >= MaxParkedProbes {
			return nil
		}
		pc.abandoned = true
		pr.probe = nil
		pr.probesParked++
		pr.probeBackoff = min(2*pr.probeBackoff, maxProbeBackoff)
		ev := log.Ctx(ctx).Warn()
		if pr.probesParked+1 >= MaxParkedProbes {
			ev = log.Ctx(ctx).Error()
		}
		ev.Str("path", pr.path).
			Int("parked-probes", pr.probesParked).
			Int("max-parked-probes", MaxParkedProbes).
			Dur("next-probe-after", pr.probeBackoff).
			Msg("file secret: remount probe blocked in the filesystem; starting another")
	} else if now.Sub(pr.lastProbeDone) < retry {
		return nil
	}
	pc := &probeCall{done: make(chan struct{}), started: now}
	pr.probe = pc
	return pc
}

// finishProbe records pc's stat of the path and, when reads are still parked
// and it resolves to a device none of them is on, lets the next fetch at the
// cap start one fresh read there.
func (pr *pathReads) finishProbe(ctx context.Context, pc *probeCall, st fileState, now time.Time) {
	if pc.abandoned {
		pr.probesParked--
		log.Ctx(ctx).Info().Str("path", pr.path).
			Dur("elapsed", time.Since(pc.started)).
			Int("parked-probes", pr.probesParked).
			Msg("file secret: parked remount probe returned")
	}
	if pr.probe == pc {
		pr.probe = nil
		pr.probeBackoff = 0
	}
	pr.lastProbeDone = now
	if len(pr.parked) > 0 && st.exists && !pr.onParkedDevice(st.dev) {
		pr.admitDev, pr.admitReady = st.dev, true
	}
}

// idle reports whether pr holds nothing worth keeping.
func (pr *pathReads) idle() bool {
	return pr.live == nil && len(pr.parked) == 0 && pr.probe == nil && pr.probesParked == 0 && !pr.admitReady
}

// onParkedDevice reports whether dev is a device some parked read is on. A
// read learns its device once it has opened the file, which on a hung NFS
// mount it usually has: it parks in read(2), not open(2). One parked in open
// matches nothing, but the read a probe then admits is attributed to the
// probe's device up front, so the next probe finding the same device is
// refused and the growth stays bounded.
func (pr *pathReads) onParkedDevice(dev uint64) bool {
	for c := range pr.parked {
		if c.devKnown && c.dev == dev {
			return true
		}
	}
	return false
}

// readCall is one read of a path. waiters counts the live callers still
// interested; when it drops to zero before the read finishes, the read is
// abandoned and moves from live to parked. dev is the device it is reading
// from, once known.
type readCall struct {
	done     chan struct{}
	started  time.Time
	waiters  int
	finished bool // set under Provider.mu once the read has returned
	parked   bool // set under Provider.mu when the last waiter abandons it
	dev      uint64
	devKnown bool
	data     []byte
	err      error
}

// probeCall is one remount probe: a stat of the path, detached like a read.
type probeCall struct {
	done      chan struct{}
	started   time.Time
	abandoned bool // set under Provider.mu when a newer probe replaces it
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
// proceeds once a parked read returns, the retry interval has passed, or the
// path has been remounted.
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
// A parked read is stuck on the mount it started on, not on the path: the
// standard recovery for a stale NFS mount is a lazy unmount and remount, after
// which the path is healthy while the old reads may never return. So at the
// cap, fetches probe the path with a stat, and once a probe finds it on a
// device no parked read is on, one fresh read is admitted there. Each read
// past the cap thus costs a remount, not a retry.
func (p *Provider) read(ctx context.Context, path string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	for probed := false; ; probed = true {
		pr, a, err := p.acquire(ctx, path, probed)
		if err != nil {
			return nil, err
		}
		if a.read != nil {
			return p.await(ctx, pr, a.read)
		}
		select {
		case <-ctx.Done():
			// The caller's own deadline ended the wait, so it must see
			// ctx.Err() as on the read path; the reads are still blocked, so
			// it wraps ErrReadBlocked too.
			return nil, fmt.Errorf("%w: %w", ErrReadBlocked, ctx.Err())
		case <-a.probe.done:
		}
	}
}

// acquire admits a fetch of path and starts whatever fresh read or probe the
// admission calls for.
func (p *Provider) acquire(ctx context.Context, path string, probed bool) (*pathReads, admission, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.reads == nil {
		p.reads = make(map[string]*pathReads)
	}
	pr := p.reads[path]
	if pr == nil {
		pr = &pathReads{path: path, parked: make(map[*readCall]struct{})}
		p.reads[path] = pr
	}
	a, err := pr.admit(ctx, time.Now(), p.retryInterval(), probed)
	if err != nil {
		return nil, admission{}, err
	}
	if a.fresh {
		go p.runRead(context.WithoutCancel(ctx), pr, a.read)
	}
	if a.probe != nil {
		go p.runProbe(context.WithoutCancel(ctx), pr, a.probe)
	}
	return pr, a, nil
}

// await waits for c within ctx and releases the caller's interest in it.
func (p *Provider) await(ctx context.Context, pr *pathReads, c *readCall) ([]byte, error) {
	select {
	case <-ctx.Done():
		p.update(pr, func() { pr.abandon(ctx, c) })
		return nil, ctx.Err()
	case <-c.done:
		// A finished read is already unlinked from pr, so there is no
		// interest left to release.
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

// runRead performs the read and retires it.
func (p *Provider) runRead(ctx context.Context, pr *pathReads, c *readCall) {
	read := p.readFile
	if read == nil {
		read = readCapped
	}
	data, err := read(pr.path, func(dev uint64) {
		p.update(pr, func() { c.dev, c.devKnown = dev, true })
	})
	p.update(pr, func() { pr.finishRead(ctx, c, data, err) })
	close(c.done)
}

// runProbe stats the path and records the verdict.
func (p *Provider) runProbe(ctx context.Context, pr *pathReads, pc *probeCall) {
	stat := p.statPath
	if stat == nil {
		stat = statFile
	}
	st := stat(pr.path)
	p.update(pr, func() { pr.finishProbe(ctx, pc, st, time.Now()) })
	close(pc.done)
}

// update applies fn to pr under p.mu, then drops pr from the provider once
// nothing for its path remains. pr may already have been dropped, and its path
// taken by a newer pathReads, when fn releases a caller whose ctx ended just as
// its read finished; the identity check keeps it from dropping the newer one.
func (p *Provider) update(pr *pathReads, fn func()) {
	p.mu.Lock()
	defer p.mu.Unlock()

	fn()
	if pr.idle() && p.reads[pr.path] == pr {
		delete(p.reads, pr.path)
	}
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
func readCapped(path string, opened func(dev uint64)) ([]byte, error) {
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
	opened(deviceOf(fi))
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
	dev     uint64
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
	st.dev = deviceOf(fi)
	return st
}

// deviceOf returns the ID of the device holding fi. A remount gets a new one,
// which is how a fetch tells a recovered path from the mount its parked reads
// are stuck on.
func deviceOf(fi fs.FileInfo) uint64 {
	if sys, ok := fi.Sys().(*syscall.Stat_t); ok {
		return devID(sys.Dev)
	}
	return 0
}

// devID widens a platform's dev_t (uint64 on Linux, int32 on Darwin) to a
// comparable ID; it is a bit pattern, not a quantity.
func devID[T ~int32 | ~uint32 | ~int64 | ~uint64](v T) uint64 {
	return uint64(v)
}
