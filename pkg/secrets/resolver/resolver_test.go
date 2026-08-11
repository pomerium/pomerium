package resolver

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"

	"github.com/pomerium/pomerium/pkg/secrets/bindings"
	"github.com/pomerium/pomerium/pkg/secrets/provider"
	"github.com/pomerium/pomerium/pkg/secrets/provider/providertest"
	"github.com/pomerium/pomerium/pkg/secrets/ref"
)

var testDefaults = bindings.Defaults{
	Refresh:     5 * time.Minute,
	StaleGrace:  30 * time.Minute,
	NegativeTTL: 30 * time.Second,
}

func testFakeRegistry(t *testing.T) (*provider.Registry, *providertest.Fake) {
	t.Helper()
	fake := providertest.New("file")
	reg := provider.NewRegistry()
	require.NoError(t, reg.Register(fake))
	return reg, fake
}

func newTestResolver(t *testing.T, reg *provider.Registry, opts ...Option) *Resolver {
	t.Helper()
	r, _ := newTestResolverReader(t, reg, opts...)
	return r
}

func newTestResolverReader(t *testing.T, reg *provider.Registry, opts ...Option) (*Resolver, *sdkmetric.ManualReader) {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	base := []Option{WithRand(constRand(0.5)), WithMeter(mp.Meter("test")), WithLogger(zerolog.Nop())}
	return New(reg, append(base, opts...)...), reader
}

func mustRefParse(t *testing.T, raw string) ref.Ref {
	t.Helper()
	r, err := ref.Parse(raw)
	require.NoError(t, err)
	return r
}

func fkOf(t *testing.T, raw string) string {
	t.Helper()
	return mustRefParse(t, raw).FetchKey()
}

func bind(t *testing.T, id, raw string) bindings.Binding {
	t.Helper()
	return bindings.Binding{ID: id, Ref: mustRefParse(t, raw)}
}

func bindTuned(t *testing.T, id, raw string, refresh, staleGrace time.Duration) bindings.Binding {
	t.Helper()
	return bindings.Binding{ID: id, Ref: mustRefParse(t, raw), Refresh: refresh, StaleGrace: staleGrace}
}

func buildScope(t *testing.T, reg *provider.Registry, bs ...bindings.Binding) *bindings.Scope {
	t.Helper()
	s, err := bindings.NewScope(nil, bs, testDefaults, reg)
	require.NoError(t, err)
	return s
}

// advance moves the fake clock forward and lets background loops settle.
func advance(d time.Duration) {
	time.Sleep(d)
	synctest.Wait()
}

func TestApplyRegistersAndFetches(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		reg, fake := testFakeRegistry(t)
		fake.SetValue(fkOf(t, "file:///a"), "v1")

		r := newTestResolver(t, reg)
		defer r.Close()

		r.Apply(context.Background(), buildScope(t, reg, bind(t, "tok", "file:///a")))
		synctest.Wait()

		got := r.Lookup("tok")
		assert.True(t, got.Found)
		assert.Equal(t, StateFresh, got.State)
		assert.Equal(t, "v1", got.Value)
		assert.Equal(t, 1, fake.FetchCount(fkOf(t, "file:///a")))
	})
}

func TestLookupUnknownID(t *testing.T) {
	t.Parallel()
	reg, _ := testFakeRegistry(t)
	r := newTestResolver(t, reg)
	defer r.Close()
	got := r.Lookup("nope")
	assert.False(t, got.Found)
}

func TestDedupeByFetchKey(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		reg, fake := testFakeRegistry(t)
		fake.SetValue(fkOf(t, "file:///a"), "shared")

		r := newTestResolver(t, reg)
		defer r.Close()

		r.Apply(context.Background(), buildScope(t, reg,
			bind(t, "a", "file:///a"),
			bind(t, "b", "file:///a"),
		))
		synctest.Wait()

		assert.Equal(t, "shared", r.Lookup("a").Value)
		assert.Equal(t, "shared", r.Lookup("b").Value)
		assert.Equal(t, 1, fake.FetchCount(fkOf(t, "file:///a")))
	})
}

func TestSharedFetchDistinctSelectors(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		reg, fake := testFakeRegistry(t)
		fake.SetValue(fkOf(t, "file:///data"), `{"a":"AAA","b":"BBB"}`)

		r := newTestResolver(t, reg)
		defer r.Close()

		r.Apply(context.Background(), buildScope(t, reg,
			bind(t, "ta", "file:///data#a"),
			bind(t, "tb", "file:///data#b"),
		))
		synctest.Wait()

		assert.Equal(t, "AAA", r.Lookup("ta").Value)
		assert.Equal(t, "BBB", r.Lookup("tb").Value)
		assert.Equal(t, 1, fake.FetchCount(fkOf(t, "file:///data")), "one underlying fetch for both selectors")
	})
}

func TestApplyDiff(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		reg, fake := testFakeRegistry(t)
		fake.SetValue(fkOf(t, "file:///a"), "va")
		fake.SetValue(fkOf(t, "file:///b"), "vb")

		r := newTestResolver(t, reg)
		defer r.Close()

		r.Apply(context.Background(), buildScope(t, reg, bind(t, "a", "file:///a")))
		synctest.Wait()
		require.Equal(t, StateFresh, r.Lookup("a").State)
		countA := fake.FetchCount(fkOf(t, "file:///a"))

		r.Apply(context.Background(), buildScope(t, reg, bind(t, "b", "file:///b")))
		synctest.Wait()
		assert.Equal(t, "vb", r.Lookup("b").Value)
		assert.False(t, r.Lookup("a").Found)

		// A's loop stopped: no further fetches after a full refresh interval.
		advance(6 * time.Minute)
		assert.Equal(t, countA, fake.FetchCount(fkOf(t, "file:///a")))
	})
}

func TestApplyRebindsURL(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		reg, fake := testFakeRegistry(t)
		fake.SetValue(fkOf(t, "file:///x"), "vx")
		fake.SetValue(fkOf(t, "file:///y"), "vy")

		r := newTestResolver(t, reg)
		defer r.Close()

		r.Apply(context.Background(), buildScope(t, reg, bind(t, "tok", "file:///x")))
		synctest.Wait()
		require.Equal(t, "vx", r.Lookup("tok").Value)

		r.Apply(context.Background(), buildScope(t, reg, bind(t, "tok", "file:///y")))
		synctest.Wait()
		assert.Equal(t, "vy", r.Lookup("tok").Value)
	})
}

func TestRefreshSwapsValue(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		reg, fake := testFakeRegistry(t)
		fk := fkOf(t, "file:///a")
		fake.SetValue(fk, "v1")

		r := newTestResolver(t, reg)
		defer r.Close()

		r.Apply(context.Background(), buildScope(t, reg, bind(t, "tok", "file:///a")))
		synctest.Wait()
		require.Equal(t, "v1", r.Lookup("tok").Value)

		fake.SetValue(fk, "v2")
		advance(5 * time.Minute)
		assert.Equal(t, "v2", r.Lookup("tok").Value)
		assert.Equal(t, StateFresh, r.Lookup("tok").State)
	})
}

func TestSelectorAppliedOnCommit(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		reg, fake := testFakeRegistry(t)
		fake.SetValue(fkOf(t, "file:///data"), `{"data":{"token":"s3cr3t"}}`)

		r := newTestResolver(t, reg)
		defer r.Close()

		r.Apply(context.Background(), buildScope(t, reg, bind(t, "tok", "file:///data#data.token")))
		synctest.Wait()
		assert.Equal(t, "s3cr3t", r.Lookup("tok").Value)
	})
}

func TestSelectorFailure(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		reg, fake := testFakeRegistry(t)
		// Not JSON: the fragment-bearing binding fails its selector, but the
		// sibling with no fragment gets the raw value fresh.
		fake.SetValue(fkOf(t, "file:///data"), `not-json`)

		r := newTestResolver(t, reg)
		defer r.Close()

		r.Apply(context.Background(), buildScope(t, reg,
			bind(t, "sel", "file:///data#data.token"),
			bind(t, "raw", "file:///data"),
		))
		synctest.Wait()

		assert.Equal(t, StateFailed, r.Lookup("sel").State, "selector error fails only that value")
		assert.Equal(t, StateFresh, r.Lookup("raw").State)
		assert.Equal(t, "not-json", r.Lookup("raw").Value)
	})
}

func TestStaleWithinGrace(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		reg, fake := testFakeRegistry(t)
		fk := fkOf(t, "file:///a")
		fake.SetValue(fk, "v1")

		r := newTestResolver(t, reg)
		defer r.Close()

		r.Apply(context.Background(), buildScope(t, reg, bindTuned(t, "tok", "file:///a", 10*time.Second, 60*time.Second)))
		synctest.Wait()
		require.Equal(t, StateFresh, r.Lookup("tok").State)

		fake.SetError(fk, errors.New("transient io error"))
		advance(11 * time.Second)

		got := r.Lookup("tok")
		assert.Equal(t, StateStale, got.State)
		assert.Equal(t, "v1", got.Value, "last-good still served")

		before := fake.FetchCount(fk)
		advance(30 * time.Second)
		assert.Greater(t, fake.FetchCount(fk), before, "keeps retrying with backoff")
	})
}

func TestExpiredAfterGrace(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		reg, fake := testFakeRegistry(t)
		fk := fkOf(t, "file:///a")
		fake.SetValue(fk, "v1")

		r := newTestResolver(t, reg)
		defer r.Close()

		r.Apply(context.Background(), buildScope(t, reg, bindTuned(t, "tok", "file:///a", 10*time.Second, 60*time.Second)))
		synctest.Wait()
		require.Equal(t, StateFresh, r.Lookup("tok").State)

		fake.SetError(fk, errors.New("io error"))
		advance(90 * time.Second)

		got := r.Lookup("tok")
		assert.Equal(t, StateExpired, got.State)
		assert.Equal(t, "", got.Value, "expired value dropped from snapshot")
	})
}

func TestRecoveryFromExpired(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		reg, fake := testFakeRegistry(t)
		fk := fkOf(t, "file:///a")
		fake.SetValue(fk, "v1")

		r := newTestResolver(t, reg)
		defer r.Close()

		r.Apply(context.Background(), buildScope(t, reg, bindTuned(t, "tok", "file:///a", 10*time.Second, 60*time.Second)))
		synctest.Wait()

		fake.SetError(fk, errors.New("io error"))
		advance(90 * time.Second)
		require.Equal(t, StateExpired, r.Lookup("tok").State)

		fake.SetValue(fk, "v2")
		advance(31 * time.Second) // past the backoff cap
		got := r.Lookup("tok")
		assert.Equal(t, StateFresh, got.State)
		assert.Equal(t, "v2", got.Value)
	})
}

func TestFailedNeverFetched(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		reg, fake := testFakeRegistry(t)
		fake.SetError(fkOf(t, "file:///a"), errors.New("io error"))

		r := newTestResolver(t, reg)
		defer r.Close()

		r.Apply(context.Background(), buildScope(t, reg, bind(t, "tok", "file:///a")))
		synctest.Wait()

		got := r.Lookup("tok")
		assert.Equal(t, StateFailed, got.State)
		assert.Equal(t, "", got.Value)
	})
}

func TestNotFoundNegativeCache(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		reg, fake := testFakeRegistry(t)
		fk := fkOf(t, "file:///a")
		fake.SetError(fk, provider.ErrNotFound)

		r := newTestResolver(t, reg)
		defer r.Close()

		r.Apply(context.Background(), buildScope(t, reg, bind(t, "tok", "file:///a")))
		synctest.Wait()
		require.Equal(t, StateFailed, r.Lookup("tok").State)

		c := fake.FetchCount(fk)
		advance(20 * time.Second) // within negative_ttl (30s)
		assert.Equal(t, c, fake.FetchCount(fk), "no provider calls inside the negative window")

		advance(15 * time.Second) // past 30s
		assert.Greater(t, fake.FetchCount(fk), c, "retried after negative_ttl")
	})
}

func TestAuthErrorNotNegativeCached(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		reg, fake := testFakeRegistry(t)
		fk := fkOf(t, "file:///a")
		fake.SetError(fk, errors.New("permission denied"))

		r := newTestResolver(t, reg)
		defer r.Close()

		r.Apply(context.Background(), buildScope(t, reg, bind(t, "tok", "file:///a")))
		synctest.Wait()

		c := fake.FetchCount(fk)
		advance(2 * time.Second) // backoff retries, no 30s freeze
		assert.Greater(t, fake.FetchCount(fk), c)
	})
}

func TestWatchTriggersImmediateRefresh(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		reg, fake := testFakeRegistry(t)
		fk := fkOf(t, "file:///a")
		fake.SetValue(fk, "v1")

		r := newTestResolver(t, reg)
		defer r.Close()

		r.Apply(context.Background(), buildScope(t, reg, bind(t, "tok", "file:///a")))
		synctest.Wait()
		require.Equal(t, "v1", r.Lookup("tok").Value)

		fake.SetValue(fk, "v2")
		fake.TriggerWatch(fk) // well before the 5m scheduled refresh
		synctest.Wait()

		assert.Equal(t, "v2", r.Lookup("tok").Value)
	})
}

func TestSingleflightCollapse(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		reg, fake := testFakeRegistry(t)
		fk := fkOf(t, "file:///a")
		fake.SetValue(fk, "v1")
		fake.Block(fk)

		r, reader := newTestResolverReader(t, reg)
		defer r.Close()

		r.Apply(context.Background(), buildScope(t, reg, bind(t, "tok", "file:///a")))
		synctest.Wait()
		require.Equal(t, 1, fake.StartedCount(fk), "leader entered provider.Fetch")

		// A watch notify while the leader is blocked collapses into it.
		fake.TriggerWatch(fk)
		synctest.Wait()
		assert.Equal(t, 1, fake.StartedCount(fk), "collapsed: still only one provider call in flight")

		fake.Release(fk)
		synctest.Wait()

		assert.Equal(t, "v1", r.Lookup("tok").Value)
		assert.GreaterOrEqual(t, counterSum(t, reader, "secrets.singleflight_collapsed"), int64(1))
	})
}

// The stale-grace window is enforced even when the failure is a not-found,
// where the negative cache suppresses intermediate fetch attempts: the
// schedule loop wakes exactly when the negative window closes, and that fetch
// re-evaluates the grace boundary.
func TestExpiredAfterGraceDuringNegativeCache(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		reg, fake := testFakeRegistry(t)
		fk := fkOf(t, "file:///a")
		fake.SetValue(fk, "v1")

		r := newTestResolver(t, reg)
		defer r.Close()

		// refresh 10s, staleGrace 30s; negativeTTL comes from testDefaults (30s).
		r.Apply(context.Background(), buildScope(t, reg,
			bindTuned(t, "tok", "file:///a", 10*time.Second, 30*time.Second)))
		synctest.Wait()
		require.Equal(t, StateFresh, r.Lookup("tok").State)

		// t=10s: the scheduled refresh returns not-found, opening a 30s
		// negative window; the value is still within grace, so it serves stale.
		fake.SetError(fk, provider.ErrNotFound)
		advance(11 * time.Second)
		require.Equal(t, StateStale, r.Lookup("tok").State)
		require.Equal(t, 2, fake.FetchCount(fk), "intermediate attempts are suppressed")

		// t=40s: the negative window closes, the loop fetches again, and the
		// grace boundary (t=30s) is now behind us.
		advance(30 * time.Second)
		got := r.Lookup("tok")
		assert.Equal(t, StateExpired, got.State)
		assert.Empty(t, got.Value, "an expired value must not be served")
		assert.Equal(t, 3, fake.FetchCount(fk))
	})
}

// A binding removed by Apply must not keep emitting cache-state events when
// its already-in-flight fetch finally returns.
func TestNoStaleEventsAfterBindingRemoval(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		reg, fake := testFakeRegistry(t)
		fk := fkOf(t, "file:///a")
		fake.SetValue(fk, "v1")

		var buf syncBuffer
		r := newTestResolver(t, reg, WithLogger(zerolog.New(&buf)))
		defer r.Close()

		r.Apply(context.Background(), buildScope(t, reg,
			bindTuned(t, "tok", "file:///a", 10*time.Second, time.Hour)))
		synctest.Wait()
		require.Equal(t, StateFresh, r.Lookup("tok").State)
		buf.buf.Reset()

		// Let the refresh timer fire into a fetch that blocks, then drop the
		// binding while that fetch is still in flight.
		fake.Block(fk)
		fake.SetError(fk, provider.ErrNotFound)
		time.Sleep(11 * time.Second)
		synctest.Wait()

		r.Apply(context.Background(), nil)
		fake.Release(fk)
		synctest.Wait()

		assert.Empty(t, buf.String(), "a removed binding must emit no further events")
		assert.False(t, r.Lookup("tok").Found)
	})
}

func TestNoStaleEventsAfterClose(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		reg, fake := testFakeRegistry(t)
		fk := fkOf(t, "file:///a")
		fake.SetValue(fk, "v1")

		var buf syncBuffer
		r, reader := newTestResolverReader(t, reg, WithLogger(zerolog.New(&buf)))

		r.Apply(context.Background(), buildScope(t, reg,
			bindTuned(t, "tok", "file:///a", 10*time.Second, time.Hour)))
		synctest.Wait()
		require.Equal(t, StateFresh, r.Lookup("tok").State)
		buf.buf.Reset()
		staleBefore := counterSum(t, reader, "secrets.serving_stale")

		// Let the refresh timer fire into a fetch that blocks, then close the
		// resolver while that fetch is still in flight.
		fake.Block(fk)
		fake.SetError(fk, provider.ErrNotFound)
		time.Sleep(11 * time.Second)
		synctest.Wait()

		r.Close()
		fake.Release(fk)
		synctest.Wait()

		assert.Empty(t, buf.String(), "a closed resolver must emit no further events")
		assert.Equal(t, staleBefore, counterSum(t, reader, "secrets.serving_stale"))
	})
}

func TestBackfilledSelectorAgesFromFetch(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		reg, fake := testFakeRegistry(t)
		fk := fkOf(t, "file:///a")
		fake.SetValue(fk, `{"a":"1","b":"2"}`)

		refresh, grace := 10*time.Minute, 60*time.Second
		r := newTestResolver(t, reg)
		defer r.Close()

		r.Apply(context.Background(), buildScope(t, reg, bindTuned(t, "a", "file:///a#a", refresh, grace)))
		synctest.Wait()
		require.Equal(t, StateFresh, r.Lookup("a").State)

		// The payload ages, still within grace, with no refresh due yet.
		advance(45 * time.Second)

		// A config change adds a selector served from that cached payload.
		r.Apply(context.Background(), buildScope(t, reg,
			bindTuned(t, "a", "file:///a#a", refresh, grace),
			bindTuned(t, "b", "file:///a#b", refresh, grace)))
		synctest.Wait()
		require.Equal(t, StateFresh, r.Lookup("b").State)
		require.Equal(t, "2", r.Lookup("b").Value)

		// A failed refresh once the payload is 65s old: past the 60s grace for
		// both selectors, because the backfilled one kept the fetch's epoch
		// rather than restarting the clock at the config change.
		fake.SetError(fk, errors.New("io error"))
		advance(20 * time.Second)
		fake.TriggerWatch(fk)
		synctest.Wait()

		assert.Equal(t, StateExpired, r.Lookup("a").State)
		assert.Equal(t, StateExpired, r.Lookup("b").State)
	})
}

func TestBackfillRejectsPayloadPastGrace(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		reg, fake := testFakeRegistry(t)
		fk := fkOf(t, "file:///a")
		fake.SetValue(fk, `{"a":"1","b":"2"}`)

		refresh, grace := 10*time.Second, 30*time.Second
		r := newTestResolver(t, reg)
		defer r.Close()

		r.Apply(context.Background(), buildScope(t, reg, bindTuned(t, "a", "file:///a#a", refresh, grace)))
		synctest.Wait()
		require.Equal(t, StateFresh, r.Lookup("a").State)

		// The backend breaks and the bound value ages out of its grace.
		fake.SetError(fk, errors.New("io error"))
		advance(60 * time.Second)
		require.Equal(t, StateExpired, r.Lookup("a").State)

		// A config change now adds a selector whose only available bytes are the
		// expired payload. It must not be served.
		r.Apply(context.Background(), buildScope(t, reg,
			bindTuned(t, "a", "file:///a#a", refresh, grace),
			bindTuned(t, "b", "file:///a#b", refresh, grace)))
		synctest.Wait()

		got := r.Lookup("b")
		assert.Equal(t, StateExpired, got.State, "a payload past grace must not be resurrected")
		assert.Empty(t, got.Value)
	})
}
