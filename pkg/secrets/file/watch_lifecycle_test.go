package file

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// watchState reports the provider's watcher bookkeeping for tests.
func (p *Provider) watchState() (nWatches, nPaths int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, pl := range p.pollers {
		nWatches += len(pl.regs)
	}
	return nWatches, len(p.pollers)
}

func TestWatchSharedPathSurvivesPartialStop(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "secret")
	require.NoError(t, os.WriteFile(path, []byte("v1"), 0o600))

	p := newTestProvider()
	var a, b atomic.Int64
	stopA, err := p.Watch(context.Background(), fileRef(t, path), func() { a.Add(1) })
	require.NoError(t, err)
	stopB, err := p.Watch(context.Background(), fileRef(t, path), func() { b.Add(1) })
	require.NoError(t, err)
	defer stopB()

	stopA()
	nWatches, nPaths := p.watchState()
	assert.Equal(t, 1, nWatches)
	assert.Equal(t, 1, nPaths, "shared path stays watched while one registration remains")

	require.NoError(t, os.WriteFile(path, []byte("v2"), 0o600))
	assert.Eventually(t, func() bool { return b.Load() > 0 }, watchWait, watchTick)
	assert.Zero(t, a.Load())
}

func TestWatchDistinctPathsSurvivePartialStop(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pa := filepath.Join(dir, "a")
	pb := filepath.Join(dir, "b")
	require.NoError(t, os.WriteFile(pa, []byte("v1"), 0o600))
	require.NoError(t, os.WriteFile(pb, []byte("v1"), 0o600))

	p := newTestProvider()
	var b atomic.Int64
	stopA, err := p.Watch(context.Background(), fileRef(t, pa), func() {})
	require.NoError(t, err)
	stopB, err := p.Watch(context.Background(), fileRef(t, pb), func() { b.Add(1) })
	require.NoError(t, err)
	defer stopB()

	stopA()
	require.NoError(t, os.WriteFile(pb, []byte("v2"), 0o600))
	assert.Eventually(t, func() bool { return b.Load() > 0 }, watchWait, watchTick)
}

func TestWatchTeardownAndRecreate(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "secret")
	require.NoError(t, os.WriteFile(path, []byte("v1"), 0o600))

	p := newTestProvider()
	_, nPaths := p.watchState()
	assert.Zero(t, nPaths, "no poller before first Watch")

	stop, err := p.Watch(context.Background(), fileRef(t, path), func() {})
	require.NoError(t, err)
	_, nPaths = p.watchState()
	assert.Equal(t, 1, nPaths)

	stop()
	stop() // idempotent
	nWatches, nPaths := p.watchState()
	assert.Zero(t, nWatches)
	assert.Zero(t, nPaths, "poller torn down after last stop")

	var count atomic.Int64
	stop2, err := p.Watch(context.Background(), fileRef(t, path), func() { count.Add(1) })
	require.NoError(t, err)
	defer stop2()
	require.NoError(t, os.WriteFile(path, []byte("v2"), 0o600))
	assert.Eventually(t, func() bool { return count.Load() > 0 }, watchWait, watchTick)
}

// The Provider doc promises that a path's poller exits when its last
// registration stops; that includes its goroutine.
func TestWatchTeardownReleasesGoroutines(t *testing.T) {
	// Not parallel: goroutine counting.
	path := filepath.Join(t.TempDir(), "secret")
	require.NoError(t, os.WriteFile(path, []byte("v1"), 0o600))

	before := runtime.NumGoroutine()
	p := newTestProvider()
	stop1, err := p.Watch(context.Background(), fileRef(t, path), func() {})
	require.NoError(t, err)
	stop2, err := p.Watch(context.Background(), fileRef(t, path), func() {})
	require.NoError(t, err)
	require.Greater(t, runtime.NumGoroutine(), before, "precondition: watching spawns goroutines")

	stop1()
	_, nPaths := p.watchState()
	assert.Equal(t, 1, nPaths, "poller survives while a registration remains")

	stop2()
	requireGoroutinesBack(t, before)
}

func TestWatchCtxCancelTearsDown(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "secret")
	require.NoError(t, os.WriteFile(path, []byte("v1"), 0o600))

	p := newTestProvider()
	ctx, cancel := context.WithCancel(context.Background())
	stop, err := p.Watch(ctx, fileRef(t, path), func() {})
	require.NoError(t, err)

	cancel()
	assert.Eventually(t, func() bool {
		nWatches, nPaths := p.watchState()
		return nWatches == 0 && nPaths == 0
	}, watchWait, watchTick, "ctx cancel must unregister and tear down the poller")

	stop() // harmless after ctx cancel
}

// Like Fetch, Watch refuses an already-done ctx instead of returning a
// registration that will never notify.
func TestWatchRejectsDoneContext(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "secret")
	require.NoError(t, os.WriteFile(path, []byte("v1"), 0o600))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	p := newTestProvider()
	stop, err := p.Watch(ctx, fileRef(t, path), func() {})
	require.ErrorIs(t, err, context.Canceled)
	require.Nil(t, stop)
	nWatches, nPaths := p.watchState()
	assert.Zero(t, nWatches)
	assert.Zero(t, nPaths)
}

// Watch must never open the watched file: on a hung mount open(2) blocks
// forever, and a FIFO with no writer reproduces that. Because nothing opens
// the FIFO, a non-blocking writer open reports ENXIO, and watching it must not
// disturb change detection on any other path.
func TestWatchNeverOpensTheFile(t *testing.T) {
	t.Parallel()

	fifo := newFIFO(t)
	good := filepath.Join(t.TempDir(), "good")
	require.NoError(t, os.WriteFile(good, []byte("v1"), 0o600))

	p := newTestProvider()
	stopFIFO, err := p.Watch(context.Background(), fileRef(t, fifo), func() {})
	require.NoError(t, err)
	defer stopFIFO()
	var count atomic.Int64
	stopGood, err := p.Watch(context.Background(), fileRef(t, good), func() { count.Add(1) })
	require.NoError(t, err)
	defer stopGood()

	require.NoError(t, os.WriteFile(good, []byte("v2"), 0o600))
	assert.Eventually(t, func() bool { return count.Load() > 0 }, watchWait, watchTick)

	fd, err := syscall.Open(fifo, syscall.O_WRONLY|syscall.O_NONBLOCK, 0)
	if err == nil {
		_ = syscall.Close(fd)
	}
	assert.ErrorIs(t, err, syscall.ENXIO, "Watch opened the file")
}

func TestWatchStopFromWithinNotify(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "secret")
	require.NoError(t, os.WriteFile(path, []byte("v1"), 0o600))

	p := newTestProvider()
	// The callback needs its own stop func, which only exists once Watch
	// returns; hand it over atomically so the poller goroutine's read is
	// synchronized with the assignment.
	var stop atomic.Pointer[func()]
	stopped := make(chan struct{})
	s, err := p.Watch(context.Background(), fileRef(t, path), func() {
		(*stop.Load())()
		close(stopped)
	})
	require.NoError(t, err)
	stop.Store(&s)

	require.NoError(t, os.WriteFile(path, []byte("v2"), 0o600))
	select {
	case <-stopped:
	case <-time.After(watchWait):
		t.Fatal("notify never fired")
	}
	_, nPaths := p.watchState()
	assert.Zero(t, nPaths, "stop() from inside notify must tear down without deadlock")
}

func TestWatchDetectsDelete(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "secret")
	require.NoError(t, os.WriteFile(path, []byte("v1"), 0o600))

	var count atomic.Int64
	stop, err := newTestProvider().Watch(context.Background(), fileRef(t, path), func() { count.Add(1) })
	require.NoError(t, err)
	defer stop()

	require.NoError(t, os.Remove(path))
	assert.Eventually(t, func() bool { return count.Load() > 0 }, watchWait, watchTick)
}

func TestWatchConcurrentRegisterAndStop(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	p := newTestProvider()
	var wg sync.WaitGroup
	for i := range 16 {
		path := filepath.Join(dir, fmt.Sprintf("s%d", i))
		require.NoError(t, os.WriteFile(path, []byte("v"), 0o600))
		wg.Go(func() {
			ctx, cancel := context.WithCancel(context.Background())
			stop, err := p.Watch(ctx, fileRef(t, path), func() {})
			assert.NoError(t, err)
			if i%2 == 0 {
				cancel()
			} else {
				stop()
				cancel()
			}
			stop()
		})
	}
	wg.Wait()
	assert.Eventually(t, func() bool {
		nWatches, nPaths := p.watchState()
		return nWatches == 0 && nPaths == 0
	}, watchWait, watchTick)
}

// provider.Watcher: no new delivery begins after stop returns. Two
// registrations on one path each stop the other from inside their callback;
// whichever runs first stops the second, so exactly one may run.
func TestWatchNoNotifyAfterStopReturns(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "secret")
	require.NoError(t, os.WriteFile(path, []byte("v1"), 0o600))

	p := newTestProvider()
	r := fileRef(t, path)

	ready := make(chan struct{}) // closed once both stop funcs exist
	var ran atomic.Int64
	var stopA, stopB func()
	var err error
	stopA, err = p.Watch(context.Background(), r, func() { <-ready; ran.Add(1); stopB() })
	require.NoError(t, err)
	stopB, err = p.Watch(context.Background(), r, func() { <-ready; ran.Add(1); stopA() })
	require.NoError(t, err)
	close(ready)
	defer stopA()
	defer stopB()

	require.NoError(t, os.WriteFile(path, []byte("v2"), 0o600))
	require.Eventually(t, func() bool { return ran.Load() >= 1 }, watchWait, watchTick)
	// A wrongly delivered second callback runs right after the first on the
	// poller goroutine.
	assert.Never(t, func() bool { return ran.Load() > 1 }, 10*testPollInterval, watchTick,
		"notify was invoked after its stop() had returned")
}
