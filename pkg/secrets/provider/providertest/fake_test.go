package providertest

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/pkg/secrets/provider"
	"github.com/pomerium/pomerium/pkg/secrets/ref"
)

const (
	wait = time.Second
	tick = time.Millisecond
)

func parseRef(t *testing.T, raw string) ref.Ref {
	t.Helper()
	return MustParseRef(t, raw)
}

func TestFakeDefaults(t *testing.T) {
	t.Parallel()

	f := New("test")
	r := parseRef(t, "test:///key")
	assert.Equal(t, "test", f.Scheme())
	assert.NoError(t, f.Validate(r))

	_, err := f.Fetch(context.Background(), r)
	assert.True(t, provider.IsNotFound(err), "unscripted key is not-found")
	assert.Equal(t, 1, f.FetchCount(r.FetchKey()))
	assert.Equal(t, 1, f.StartedCount(r.FetchKey()))

	f.SetValidateErr(assert.AnError)
	assert.ErrorIs(t, f.Validate(r), assert.AnError)
	f.SetValidateErr(nil)
	assert.NoError(t, f.Validate(r))
}

// A new value must yield a new Version, and provider.Result.Version is
// documented as never containing secret material (it is meant for logs and
// metrics). SetValue currently copies the value into Version.
func TestFakeSetValueVersion(t *testing.T) {
	t.Parallel()

	f := New("test")
	r := parseRef(t, "test:///key")

	const secret = "hunter2-do-not-log"
	f.SetValue(r.FetchKey(), secret)
	a, err := f.Fetch(context.Background(), r)
	require.NoError(t, err)
	assert.Equal(t, secret, string(a.Value))
	assert.NotContains(t, a.Version, secret, "Result.Version must never contain secret material")

	f.SetValue(r.FetchKey(), "v2")
	b, err := f.Fetch(context.Background(), r)
	require.NoError(t, err)
	assert.Equal(t, "v2", string(b.Value))
	assert.NotEqual(t, a.Version, b.Version, "changed value -> changed version")
}

func TestFakeFragmentSharesFetchKey(t *testing.T) {
	t.Parallel()

	f := New("test")
	r1 := parseRef(t, "test:///key#a")
	r2 := parseRef(t, "test:///key#b")
	f.SetValue(r1.FetchKey(), "v")
	res, err := f.Fetch(context.Background(), r2)
	require.NoError(t, err)
	assert.Equal(t, "v", string(res.Value))
	assert.Equal(t, 1, f.FetchCount(r1.FetchKey()))
}

// The real file provider returns ctx.Err() for an already-cancelled context
// without touching the backend. The Fake consults ctx only while Blocked, so a
// resolver test relying on "a cancelled fetch fails and does not count" passes
// against the real provider and silently gets a value from the Fake.
func TestFakeFetchHonoursCancelledContext(t *testing.T) {
	t.Parallel()

	f := New("test")
	r := parseRef(t, "test:///key")
	f.SetValue(r.FetchKey(), "v1")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	res, err := f.Fetch(ctx, r)
	assert.ErrorIs(t, err, context.Canceled, "Fake.Fetch returned %q for a cancelled ctx", res.Value)
	assert.Empty(t, res.Value)
	assert.Zero(t, f.FetchCount(r.FetchKey()), "a cancelled fetch must not count as completed")
}

func TestFakeBlockAndCancel(t *testing.T) {
	t.Parallel()

	f := New("test")
	r := parseRef(t, "test:///key")
	f.SetValue(r.FetchKey(), "v")
	f.Block(r.FetchKey())
	f.Block(r.FetchKey()) // idempotent

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := f.Fetch(ctx, r)
		done <- err
	}()
	assert.Eventually(t, func() bool { return f.StartedCount(r.FetchKey()) == 1 }, wait, tick)
	assert.Zero(t, f.FetchCount(r.FetchKey()))
	cancel()
	assert.ErrorIs(t, <-done, context.Canceled)
	assert.Zero(t, f.FetchCount(r.FetchKey()), "cancelled fetch is started but not completed")

	f.Release(r.FetchKey())
	f.Release(r.FetchKey()) // release without block is a no-op
	res, err := f.Fetch(context.Background(), r)
	require.NoError(t, err)
	assert.Equal(t, "v", string(res.Value))
}

func TestFakeReleaseUnblocksAll(t *testing.T) {
	t.Parallel()

	f := New("test")
	r := parseRef(t, "test:///key")
	f.SetValue(r.FetchKey(), "v")
	f.Block(r.FetchKey())

	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := f.Fetch(context.Background(), r)
			assert.NoError(t, err)
		}()
	}
	assert.Eventually(t, func() bool { return f.StartedCount(r.FetchKey()) == 4 }, wait, tick)
	f.Release(r.FetchKey())
	wg.Wait()
	assert.Equal(t, 4, f.FetchCount(r.FetchKey()))
}

func TestFakeWatchStopIdempotentAndScoped(t *testing.T) {
	t.Parallel()

	f := New("test")
	r := parseRef(t, "test:///key")
	other := parseRef(t, "test:///other")
	var a, b atomic.Int64
	stopA, err := f.Watch(context.Background(), r, func() { a.Add(1) })
	require.NoError(t, err)
	stopB, err := f.Watch(context.Background(), other, func() { b.Add(1) })
	require.NoError(t, err)
	defer stopB()

	f.TriggerWatch(r.FetchKey())
	assert.Equal(t, int64(1), a.Load())
	assert.Zero(t, b.Load(), "trigger is scoped to its fetchKey")

	stopA()
	stopA()
	f.TriggerWatch(r.FetchKey())
	f.TriggerWatch("never-registered")
	assert.Equal(t, int64(1), a.Load())
}

// The Fake must honour the provider.Watcher contract ("until ctx is done or
// the returned stop func is called") so that a test which stops a watch by
// cancelling its context does not pass against the Fake while diverging from
// the real file provider.
func TestFakeWatchHonoursContextCancel(t *testing.T) {
	t.Parallel()

	f := New("test")
	r := parseRef(t, "test:///key")

	ctx, cancel := context.WithCancel(context.Background())
	var count atomic.Int64
	stop, err := f.Watch(ctx, r, func() { count.Add(1) })
	require.NoError(t, err)
	defer stop()

	cancel()
	// context.AfterFunc runs teardown on its own goroutine, so poll until a
	// trigger stops reaching the callback. Without the ctx wiring every
	// trigger increments the counter and this never converges.
	assert.Eventually(t, func() bool {
		before := count.Load()
		f.TriggerWatch(r.FetchKey())
		return count.Load() == before
	}, wait, tick, "notify still fires after ctx was cancelled")
}

// provider.Watcher: no new delivery begins after stop returns. Two
// registrations on one key each stop the other from inside their callback;
// whichever runs first stops the second, so exactly one may run. TriggerWatch
// delivers synchronously on this goroutine, so plain locals suffice.
func TestFakeNoNotifyAfterStopReturns(t *testing.T) {
	t.Parallel()

	f := New("test")
	r := parseRef(t, "test:///key")

	var ran int
	var stopA, stopB func()
	var err error
	stopA, err = f.Watch(context.Background(), r, func() { ran++; stopB() })
	require.NoError(t, err)
	stopB, err = f.Watch(context.Background(), r, func() { ran++; stopA() })
	require.NoError(t, err)

	f.TriggerWatch(r.FetchKey())
	assert.Equal(t, 1, ran, "notify was invoked after its stop() had returned")
}

// A zero-value Fake has nil maps: every scripting or fetch call panics, and
// nothing steers callers to New.
func TestZeroValueFake(t *testing.T) {
	t.Parallel()

	var f Fake
	assert.NotPanics(t, func() { f.SetValue("k", "v") }, "SetValue on zero-value Fake")
	assert.NotPanics(t, func() {
		_, _ = f.Fetch(context.Background(), parseRef(t, "test:///k"))
	}, "Fetch on zero-value Fake")
}
