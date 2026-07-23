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
