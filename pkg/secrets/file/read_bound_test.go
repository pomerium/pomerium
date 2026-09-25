package file

import (
	"bytes"
	"context"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/pkg/secrets/ref"
)

// blockedReads stands in for a wedged NFS/FUSE mount: a read that has entered
// an uninterruptible syscall and will not return until the mount recovers.
// There is no portable way to wedge a real mount in a unit test, and the one
// special file that does block (a FIFO) is now refused before any read.
type blockedReads struct {
	release chan struct{}
	active  atomic.Int64
	started chan struct{}
	once    sync.Once
}

func newBlockedReads() *blockedReads {
	return &blockedReads{release: make(chan struct{}), started: make(chan struct{})}
}

func (b *blockedReads) read(string, func(uint64)) ([]byte, error) {
	b.active.Add(1)
	defer b.active.Add(-1)
	b.once.Do(func() { close(b.started) })
	<-b.release
	return []byte("recovered"), nil
}

// Retrying against a wedged mount must pin a fixed number of goroutines and
// descriptors per path, not one per attempt.
func TestFetchBoundsAbandonedReads(t *testing.T) {
	t.Parallel()

	b := newBlockedReads()
	defer close(b.release)

	// No spacing between retries, so only MaxParkedReads bounds them.
	p := &Provider{readFile: b.read, parkedRetryInterval: time.Nanosecond}
	r := fileRef(t, filepath.Join(t.TempDir(), "secret"))

	const attempts = 3 * MaxParkedReads
	for range attempts {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		_, err := p.Fetch(ctx, r)
		cancel()
		require.Error(t, err)
	}

	assert.LessOrEqual(t, b.active.Load(), int64(MaxParkedReads),
		"%d retries against one wedged path left %d reads parked", attempts, b.active.Load())

	_, err := p.Fetch(context.Background(), r)
	assert.ErrorIs(t, err, ErrReadBlocked, "a path at the parked cap must fail fast")
}

// Retries inside the retry interval fail fast rather than parking another
// read, so a tight retry loop costs one parked read, not MaxParkedReads.
func TestFetchSpacesRetriesWhileParked(t *testing.T) {
	t.Parallel()

	b := newBlockedReads()
	defer close(b.release)

	p := &Provider{readFile: b.read, parkedRetryInterval: time.Hour}
	r := fileRef(t, filepath.Join(t.TempDir(), "secret"))

	for range 5 {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		_, err := p.Fetch(ctx, r)
		cancel()
		require.Error(t, err)
	}
	assert.Equal(t, int64(1), b.active.Load())
}

// A parked read is stuck on the mount it started on, not on the path. After
// the standard stale-NFS recovery (lazy unmount, remount) the path is healthy
// while the old read may never return, so a later fetch must reach the new
// mount rather than fail with ErrReadBlocked until the process restarts.
func TestFetchRecoversAfterRemount(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	defer close(release)
	var calls atomic.Int64
	p := &Provider{
		parkedRetryInterval: 50 * time.Millisecond,
		readFile: func(string, func(uint64)) ([]byte, error) {
			if calls.Add(1) == 1 {
				<-release // wedged on the old mount, never returns
			}
			return []byte("remounted"), nil
		},
	}
	r := fileRef(t, filepath.Join(t.TempDir(), "secret"))

	ctx1, cancel1 := context.WithTimeout(context.Background(), 20*time.Millisecond)
	_, err := p.Fetch(ctx1, r)
	cancel1()
	require.ErrorIs(t, err, context.DeadlineExceeded)

	assert.Eventually(t, func() bool {
		res, err := p.Fetch(context.Background(), r)
		return err == nil && string(res.Value) == "remounted"
	}, 5*time.Second, 10*time.Millisecond, "path never recovered while the old read stayed parked")
}

// mount stands in for the filesystem behind one path: reads and stats on the
// current device either answer or park until release, and remount swaps in a
// healthy device while everything parked on the old one stays parked.
type mount struct {
	release chan struct{}
	dev     atomic.Uint64
	wedged  atomic.Bool
	// statWedged makes stats park too, rather than answering from the
	// attribute cache the way a hung NFS mount usually still does.
	statWedged atomic.Bool
	reads      atomic.Int64
	stats      atomic.Int64
}

func newMount() *mount {
	m := &mount{release: make(chan struct{})}
	m.dev.Store(1)
	return m
}

// read opens the file (reporting its device, as fstat would) and then parks
// in read(2) if the mount is wedged — where a hung NFS read usually sticks.
func (m *mount) read(_ string, opened func(uint64)) ([]byte, error) {
	m.reads.Add(1)
	dev := m.dev.Load()
	opened(dev)
	if m.wedged.Load() {
		<-m.release
	}
	return []byte("dev" + strconv.FormatUint(dev, 10)), nil
}

func (m *mount) stat(string) fileState {
	m.stats.Add(1)
	dev := m.dev.Load()
	if m.statWedged.Load() {
		<-m.release
	}
	return fileState{exists: true, dev: dev}
}

func (m *mount) remount() {
	m.dev.Add(1)
	m.wedged.Store(false)
	m.statWedged.Store(false)
}

func (m *mount) provider() *Provider {
	return &Provider{readFile: m.read, statPath: m.stat, parkedRetryInterval: 10 * time.Millisecond}
}

// fillParkedCap wedges m and abandons MaxParkedReads reads of r, leaving the
// path at the parked cap.
func fillParkedCap(t *testing.T, p *Provider, m *mount, r ref.Ref) {
	t.Helper()
	m.wedged.Store(true)
	for range MaxParkedReads {
		time.Sleep(2 * p.retryInterval()) // let the retry spacing admit the next read
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		_, err := p.Fetch(ctx, r)
		cancel()
		require.ErrorIs(t, err, context.DeadlineExceeded)
	}
	require.Equal(t, int64(MaxParkedReads), m.reads.Load()-1, "expected the cap of parked reads after one healthy read")
}

// At the parked cap, a remounted path must still be reached: the parked reads
// are stuck on the old mount, not on the path.
func TestFetchRecoversAfterRemountAtParkedCap(t *testing.T) {
	t.Parallel()

	m := newMount()
	defer close(m.release)
	p := m.provider()
	r := fileRef(t, filepath.Join(t.TempDir(), "secret"))

	_, err := p.Fetch(context.Background(), r) // healthy: the path is on dev 1
	require.NoError(t, err)
	fillParkedCap(t, p, m, r)

	var logs syncBuffer
	m.remount()
	res, err := p.Fetch(zerolog.New(&logs).WithContext(context.Background()), r)
	require.NoError(t, err, "the first fetch after a remount waits on one probe and reads the new mount")
	assert.Equal(t, "dev2", string(res.Value))
	assert.Contains(t, logs.String(), "different device than its blocked reads", "a remount recovery must be logged")
}

// The path is wedged from the very first read: a remount must still recover
// it.
func TestFetchRecoversAfterRemountAtParkedCapWithoutKnownDevice(t *testing.T) {
	t.Parallel()

	m := newMount()
	defer close(m.release)
	p := m.provider()
	r := fileRef(t, filepath.Join(t.TempDir(), "secret"))

	m.wedged.Store(true)
	for range MaxParkedReads {
		time.Sleep(2 * p.retryInterval())
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		_, err := p.Fetch(ctx, r)
		cancel()
		require.ErrorIs(t, err, context.DeadlineExceeded)
	}

	m.remount()
	res, err := p.Fetch(context.Background(), r)
	require.NoError(t, err)
	assert.Equal(t, "dev2", string(res.Value))
}

// A wedged mount that still answers stat from its attribute cache reports the
// same device, so retries at the cap must never admit another read onto it:
// only a remount buys a read past the cap.
func TestFetchAtParkedCapStaysBoundedWithoutRemount(t *testing.T) {
	t.Parallel()

	m := newMount()
	defer close(m.release)
	p := m.provider()
	r := fileRef(t, filepath.Join(t.TempDir(), "secret"))

	_, err := p.Fetch(context.Background(), r)
	require.NoError(t, err)
	fillParkedCap(t, p, m, r)

	deadline := time.Now().Add(300 * time.Millisecond) // ~30 retry intervals
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		_, err := p.Fetch(ctx, r)
		cancel()
		require.ErrorIs(t, err, ErrReadBlocked)
		time.Sleep(5 * time.Millisecond)
	}
	assert.Equal(t, int64(1+MaxParkedReads), m.reads.Load(), "a wedged mount was read past the parked cap")
	assert.Greater(t, m.stats.Load(), int64(1), "the cap should keep probing for a remount")
}

// Reads parked in open(2) never learn their device, so a probe may admit one
// more read — attributed to the probe's device — but no more: a mount wedged in
// open that still answers stat stays bounded.
func TestFetchAtParkedCapWithUnknownDevicesAdmitsOnce(t *testing.T) {
	t.Parallel()

	m := newMount()
	defer close(m.release)
	stuckInOpen := func(_ string, _ func(uint64)) ([]byte, error) {
		m.reads.Add(1)
		<-m.release
		return nil, nil
	}
	p := &Provider{readFile: stuckInOpen, statPath: m.stat, parkedRetryInterval: 10 * time.Millisecond}
	r := fileRef(t, filepath.Join(t.TempDir(), "secret"))

	for range 50 {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		_, _ = p.Fetch(ctx, r)
		cancel()
		time.Sleep(5 * time.Millisecond)
	}
	assert.Equal(t, int64(MaxParkedReads+1), m.reads.Load())
}

// A probe that started before the remount is itself stuck on the old mount;
// it must not keep a later probe from reaching the new one.
func TestFetchRecoversWhenFirstProbeIsStuck(t *testing.T) {
	t.Parallel()

	m := newMount()
	defer close(m.release)
	p := m.provider()
	r := fileRef(t, filepath.Join(t.TempDir(), "secret"))

	_, err := p.Fetch(context.Background(), r)
	require.NoError(t, err)
	fillParkedCap(t, p, m, r)

	m.statWedged.Store(true)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	_, err = p.Fetch(ctx, r) // starts a probe that parks on the old mount
	cancel()
	require.ErrorIs(t, err, ErrReadBlocked)

	m.remount()
	assert.Eventually(t, func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		res, err := p.Fetch(ctx, r)
		return err == nil && string(res.Value) == "dev2"
	}, 5*time.Second, 10*time.Millisecond, "a stuck probe blocked recovery")
}

// Only the fetch that starts a probe waits on it: while it is stuck, every
// other fetch at the cap must still fail fast.
func TestFetchDoesNotWaitOnAnotherFetchsProbe(t *testing.T) {
	t.Parallel()

	m := newMount()
	defer close(m.release)
	p := &Provider{readFile: m.read, statPath: m.stat, parkedRetryInterval: time.Hour}
	r := fileRef(t, filepath.Join(t.TempDir(), "secret"))

	_, err := p.Fetch(context.Background(), r)
	require.NoError(t, err)
	m.wedged.Store(true)
	m.statWedged.Store(true)
	p.parkedRetryInterval = time.Nanosecond
	for range MaxParkedReads {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		_, _ = p.Fetch(ctx, r)
		cancel()
	}
	p.parkedRetryInterval = time.Hour // the stuck probe is not replaced during the test

	ctx1, cancel1 := context.WithTimeout(context.Background(), 20*time.Millisecond)
	_, err = p.Fetch(ctx1, r) // starts the probe, which parks
	cancel1()
	require.ErrorIs(t, err, ErrReadBlocked)

	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	start := time.Now()
	_, err = p.Fetch(ctx2, r)
	require.ErrorIs(t, err, ErrReadBlocked)
	assert.Less(t, time.Since(start), time.Second, "fetch waited on another fetch's stuck probe")
}

// A fetch cancelled while waiting on its probe reports its own cancellation,
// as it would while waiting on a read, and still says the reads are blocked.
func TestFetchProbeWaitReturnsContextError(t *testing.T) {
	t.Parallel()

	m := newMount()
	defer close(m.release)
	p := m.provider()
	r := fileRef(t, filepath.Join(t.TempDir(), "secret"))

	_, err := p.Fetch(context.Background(), r)
	require.NoError(t, err)
	fillParkedCap(t, p, m, r)

	m.statWedged.Store(true)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err = p.Fetch(ctx, r)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.ErrorIs(t, err, ErrReadBlocked)
}

// lateCancelCtx reports cancellation from Err without ever firing Done. It
// stands in for a deadline that passes just after a probe has woken the fetch
// waiting on it, a window no real ctx can be made to hit on demand. That
// breaks the context.Context contract, so it is fit only for this test.
type lateCancelCtx struct {
	context.Context
	cancelled atomic.Bool
}

func (*lateCancelCtx) Done() <-chan struct{} { return nil }

func (c *lateCancelCtx) Err() error {
	if c.cancelled.Load() {
		return context.Canceled
	}
	return nil
}

// A fetch whose ctx ends as the probe it waited on returns must fail without
// spending the read that probe let through: the next fetch should get it.
func TestFetchProbeWaitDoesNotSpendAdmissionOnceCancelled(t *testing.T) {
	t.Parallel()

	m := newMount()
	defer close(m.release)
	p := m.provider()
	ctx := &lateCancelCtx{Context: context.Background()}
	p.statPath = func(path string) fileState {
		st := m.stat(path)
		ctx.cancelled.Store(true)
		return st
	}
	r := fileRef(t, filepath.Join(t.TempDir(), "secret"))

	_, err := p.Fetch(context.Background(), r)
	require.NoError(t, err)
	fillParkedCap(t, p, m, r)
	m.remount()

	reads := m.reads.Load()
	_, err = p.Fetch(ctx, r)
	require.ErrorIs(t, err, context.Canceled)
	require.ErrorIs(t, err, ErrReadBlocked)
	assert.Equal(t, reads, m.reads.Load(), "a fetch that had given up started a read")

	res, err := p.Fetch(context.Background(), r)
	require.NoError(t, err, "the read the probe let through must still be there")
	assert.Equal(t, "dev2", string(res.Value))
}

// Stuck probes are bounded too: they hold no descriptor, but each pins a
// goroutine and thread.
func TestFetchBoundsParkedProbes(t *testing.T) {
	t.Parallel()

	m := newMount()
	defer close(m.release)
	p := &Provider{readFile: m.read, statPath: m.stat, parkedRetryInterval: time.Nanosecond}
	r := fileRef(t, filepath.Join(t.TempDir(), "secret"))

	_, err := p.Fetch(context.Background(), r)
	require.NoError(t, err)
	m.wedged.Store(true)
	m.statWedged.Store(true)
	for range 10 * MaxParkedProbes {
		ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
		_, _ = p.Fetch(ctx, r)
		cancel()
	}
	assert.LessOrEqual(t, m.stats.Load(), int64(MaxParkedProbes))
	assert.Equal(t, int64(1+MaxParkedReads), m.reads.Load())
}

// Abandoning a read, retrying past a parked one, and a parked read finally
// returning are all logged: they are the only evidence of a wedged mount.
func TestFetchLogsParkedReads(t *testing.T) {
	t.Parallel()

	var buf syncBuffer
	ctx := zerolog.New(&buf).WithContext(context.Background())

	b := newBlockedReads()
	p := &Provider{readFile: b.read, parkedRetryInterval: time.Nanosecond}
	path := filepath.Join(t.TempDir(), "secret")
	r := fileRef(t, path)

	for range 2 {
		ctx1, cancel1 := context.WithTimeout(ctx, 20*time.Millisecond)
		_, err := p.Fetch(ctx1, r)
		cancel1()
		require.ErrorIs(t, err, context.DeadlineExceeded)
	}
	close(b.release)
	assert.Eventually(t, func() bool {
		return strings.Count(buf.String(), "parked read returned") == 2
	}, 5*time.Second, 10*time.Millisecond)

	out := buf.String()
	assert.Equal(t, 2, strings.Count(out, "read abandoned while blocked"), out)
	assert.Equal(t, 1, strings.Count(out, "retrying with a fresh read"), out)
	assert.Contains(t, out, `"path":"`+path+`"`)
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// A later fetch must neither join the abandoned read nor wait on it: stale work
// must never answer a fresh request.
func TestFetchDoesNotJoinAbandonedRead(t *testing.T) {
	t.Parallel()

	b := newBlockedReads()
	defer close(b.release)

	p := &Provider{readFile: b.read}
	r := fileRef(t, filepath.Join(t.TempDir(), "secret"))

	ctx1, cancel1 := context.WithTimeout(context.Background(), 20*time.Millisecond)
	_, err := p.Fetch(ctx1, r)
	cancel1()
	require.ErrorIs(t, err, context.DeadlineExceeded)
	<-b.started

	// A generous deadline: joining the stuck read would burn all of it.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	start := time.Now()
	_, err = p.Fetch(ctx2, r)
	require.ErrorIs(t, err, ErrReadBlocked)
	assert.Less(t, time.Since(start), time.Second, "fetch waited on the abandoned read")
}

// When the stuck read finally returns the path clears, so the very next fetch
// reads normally. Recovery must not require a process restart.
func TestFetchRecoversWhenBlockedReadReturns(t *testing.T) {
	t.Parallel()

	b := newBlockedReads()
	p := &Provider{readFile: b.read}
	r := fileRef(t, filepath.Join(t.TempDir(), "secret"))

	ctx1, cancel1 := context.WithTimeout(context.Background(), 20*time.Millisecond)
	_, err := p.Fetch(ctx1, r)
	cancel1()
	require.Error(t, err)
	<-b.started

	close(b.release) // the mount recovers
	assert.Eventually(t, func() bool {
		res, err := p.Fetch(context.Background(), r)
		return err == nil && string(res.Value) == "recovered"
	}, 5*time.Second, 10*time.Millisecond, "path never recovered after the blocked read returned")
}

// Concurrent live callers share one read: a fan-out over one path must cost one
// descriptor, not one per binding.
func TestFetchSharesOneReadAcrossConcurrentCallers(t *testing.T) {
	t.Parallel()

	var reads atomic.Int64
	gate := make(chan struct{})
	p := &Provider{readFile: func(string, func(uint64)) ([]byte, error) {
		reads.Add(1)
		<-gate
		return []byte("v"), nil
	}}
	path := filepath.Join(t.TempDir(), "secret")
	r := fileRef(t, path)

	const callers = 8
	var wg sync.WaitGroup
	for range callers {
		wg.Go(func() {
			res, err := p.Fetch(context.Background(), r)
			assert.NoError(t, err)
			assert.Equal(t, "v", string(res.Value))
		})
	}
	// Release the read only once every caller has joined it; a caller that
	// arrives after it finished rightly starts a fresh one.
	require.Eventually(t, func() bool {
		p.reads.mu.Lock()
		defer p.reads.mu.Unlock()
		pr := p.reads.paths[path]
		return pr != nil && pr.live != nil && pr.live.waiters == callers
	}, 3*time.Second, 10*time.Millisecond)
	close(gate)
	wg.Wait()
	assert.Equal(t, int64(1), reads.Load(), "concurrent fetches of one path must share a read")
}
