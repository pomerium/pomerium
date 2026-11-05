package file

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func (b *blockedReads) read(string) ([]byte, error) {
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

// At the parked cap a fetch fails fast and starts nothing, whatever the path
// now resolves to: the cap is a hard bound on what one wedged path can pin,
// and only a parked read returning reopens the path.
func TestFetchAtParkedCapStartsNothing(t *testing.T) {
	t.Parallel()

	b := newBlockedReads()
	p := &Provider{readFile: b.read, parkedRetryInterval: time.Nanosecond}
	path := filepath.Join(t.TempDir(), "secret")
	require.NoError(t, os.WriteFile(path, []byte("v"), 0o600)) // the path itself stats healthy
	r := fileRef(t, path)

	for range MaxParkedReads {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		_, err := p.Fetch(ctx, r)
		cancel()
		require.ErrorIs(t, err, context.DeadlineExceeded)
	}

	for range 3 {
		// A generous deadline: waiting on anything would burn all of it.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		start := time.Now()
		_, err := p.Fetch(ctx, r)
		cancel()
		require.ErrorIs(t, err, ErrReadBlocked)
		assert.Less(t, time.Since(start), time.Second, "a fetch at the parked cap must fail fast")
	}
	assert.Equal(t, int64(MaxParkedReads), b.active.Load(), "a read was started past the parked cap")

	close(b.release)
	assert.Eventually(t, func() bool {
		res, err := p.Fetch(context.Background(), r)
		return err == nil && string(res.Value) == "recovered"
	}, 5*time.Second, 10*time.Millisecond, "the path never reopened once its parked reads returned")
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

// Below the parked cap, a read that never returns must not keep a later fetch
// from reading the path once the retry interval has passed.
func TestFetchReadsPastParkedRead(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	defer close(release)
	var calls atomic.Int64
	p := &Provider{
		parkedRetryInterval: 50 * time.Millisecond,
		readFile: func(string) ([]byte, error) {
			if calls.Add(1) == 1 {
				<-release // wedged, never returns
			}
			return []byte("fresh"), nil
		},
	}
	r := fileRef(t, filepath.Join(t.TempDir(), "secret"))

	ctx1, cancel1 := context.WithTimeout(context.Background(), 20*time.Millisecond)
	_, err := p.Fetch(ctx1, r)
	cancel1()
	require.ErrorIs(t, err, context.DeadlineExceeded)

	assert.Eventually(t, func() bool {
		res, err := p.Fetch(context.Background(), r)
		return err == nil && string(res.Value) == "fresh"
	}, 5*time.Second, 10*time.Millisecond, "path never recovered while the old read stayed parked")
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
	p := &Provider{readFile: func(string) ([]byte, error) {
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
