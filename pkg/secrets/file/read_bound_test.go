package file

import (
	"context"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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

// Retrying against a wedged mount must cost one parked goroutine and
// descriptor per path, not one per attempt: unbounded growth is what exhausted
// csi-driver-nfs (#1271).
func TestFetchBoundsAbandonedReads(t *testing.T) {
	t.Parallel()

	b := newBlockedReads()
	defer close(b.release)

	p := &Provider{readFile: b.read}
	r := fileRef(t, filepath.Join(t.TempDir(), "secret"))

	const attempts = 5
	for range attempts {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		_, err := p.Fetch(ctx, r)
		cancel()
		require.Error(t, err)
	}

	assert.LessOrEqual(t, b.active.Load(), int64(1),
		"%d retries against one wedged path left %d reads parked", attempts, b.active.Load())
}

// A later fetch must neither join the abandoned read nor wait on it: stale work
// must never answer a fresh request (golang/go#22724).
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
	r := fileRef(t, filepath.Join(t.TempDir(), "secret"))

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := p.Fetch(context.Background(), r)
			assert.NoError(t, err)
			assert.Equal(t, "v", string(res.Value))
		}()
	}
	assert.Eventually(t, func() bool { return reads.Load() == 1 }, 3*time.Second, 10*time.Millisecond)
	close(gate)
	wg.Wait()
	assert.Equal(t, int64(1), reads.Load(), "concurrent fetches of one path must share a read")
}
