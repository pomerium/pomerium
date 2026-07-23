package resolver

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/pomerium/pomerium/pkg/secrets/provider"
)

func sprintfPlus(v any) string { return fmt.Sprintf("%+v", v) }

// counterSum collects the reader and returns the summed value of an int64 sum
// instrument by name (0 if absent).
func counterSum(t *testing.T, reader *sdkmetric.ManualReader, name string) int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &rm))
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != name {
				continue
			}
			if d, ok := m.Data.(metricdata.Sum[int64]); ok {
				var sum int64
				for _, dp := range d.DataPoints {
					sum += dp.Value
				}
				return sum
			}
		}
	}
	return 0
}

func metricNames(t *testing.T, reader *sdkmetric.ManualReader) map[string]bool {
	t.Helper()
	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &rm))
	names := map[string]bool{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			names[m.Name] = true
		}
	}
	return names
}

func TestMetrics(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		reg, fake := testFakeRegistry(t)
		fk := fkOf(t, "file:///a")
		fake.SetValue(fk, "v1")

		r, reader := newTestResolverReader(t, reg)
		defer r.Close()

		r.Apply(context.Background(), buildScope(t, reg, bind(t, "tok", "file:///a")))
		synctest.Wait()

		// A manual reader only reports instruments that recorded data, so this
		// success scenario covers the always-firing instruments; the stale,
		// negative-cache, and singleflight instruments are covered by the
		// scenarios that exercise them below and in TestSingleflightCollapse.
		names := metricNames(t, reader)
		for _, want := range []string{
			"secrets.fetches",
			"secrets.fetch.duration",
			"secrets.refs_registered",
			"secrets.cache_state",
		} {
			assert.True(t, names[want], "instrument %q must be registered", want)
		}
		assert.GreaterOrEqual(t, counterSum(t, reader, "secrets.fetches"), int64(1))
	})
}

func TestMetricsNegativeCacheHits(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		reg, fake := testFakeRegistry(t)
		fk := fkOf(t, "file:///a")
		fake.SetError(fk, provider.ErrNotFound)

		r, reader := newTestResolverReader(t, reg)
		defer r.Close()

		r.Apply(context.Background(), buildScope(t, reg, bind(t, "tok", "file:///a")))
		synctest.Wait() // initial not-found sets the negative window

		fake.TriggerWatch(fk) // a trigger inside the window is suppressed
		synctest.Wait()

		assert.GreaterOrEqual(t, counterSum(t, reader, "secrets.negative_cache_hits"), int64(1))
	})
}

func TestMetricsStaleAndNegative(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		reg, fake := testFakeRegistry(t)
		fk := fkOf(t, "file:///a")
		fake.SetValue(fk, "v1")

		r, reader := newTestResolverReader(t, reg)
		defer r.Close()

		r.Apply(context.Background(), buildScope(t, reg, bindTuned(t, "tok", "file:///a", 10*time.Second, time.Hour)))
		synctest.Wait()

		fake.SetError(fk, errors.New("io error"))
		advance(11 * time.Second)
		require.Equal(t, StateStale, r.Lookup("tok").State)
		assert.GreaterOrEqual(t, counterSum(t, reader, "secrets.serving_stale"), int64(1))
	})
}

func TestLogTransitions(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		reg, fake := testFakeRegistry(t)
		fk := fkOf(t, "file:///a")
		fake.SetValue(fk, "v1")

		var buf syncBuffer
		logger := zerolog.New(&buf)

		r := newTestResolver(t, reg, WithLogger(logger))
		defer r.Close()

		r.Apply(context.Background(), buildScope(t, reg, bindTuned(t, "tok", "file:///a", 10*time.Second, 60*time.Second)))
		synctest.Wait()

		fake.SetError(fk, errors.New("io error"))
		advance(11 * time.Second) // -> Stale (WARN)
		advance(90 * time.Second) // -> Expired (ERROR)

		fake.SetValue(fk, "v2")
		advance(31 * time.Second) // -> Fresh recovery (INFO)

		out := buf.String()
		assert.Equal(t, 1, strings.Count(out, "secret resolved"), "INFO once on first success")
		assert.Contains(t, out, "secret serving stale")
		assert.Contains(t, out, "secret expired")
		assert.Contains(t, out, "secret recovered")
	})
}

func TestNoValueInLogs(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		const sentinel = "SENTINEL-s3cr3t"

		reg, fake := testFakeRegistry(t)
		fk := fkOf(t, "file:///a")
		fake.SetValue(fk, sentinel)

		var buf syncBuffer
		logger := zerolog.New(&buf)

		r := newTestResolver(t, reg, WithLogger(logger))
		defer r.Close()

		r.Apply(context.Background(), buildScope(t, reg, bindTuned(t, "tok", "file:///a", 10*time.Second, 60*time.Second)))
		synctest.Wait()
		require.Equal(t, sentinel, r.Lookup("tok").Value)

		fake.SetError(fk, errors.New("io error"))
		advance(11 * time.Second) // stale
		advance(90 * time.Second) // expired
		fake.SetValue(fk, sentinel)
		advance(31 * time.Second) // recovery

		assert.NotContains(t, buf.String(), sentinel, "secret value must never appear in logs")

		// Struct dumps must not leak the value either.
		assert.NotContains(t, dumpResolver(r), sentinel)
	})
}

// dumpResolver renders the resolver's internal state with %+v so the redaction
// wrappers are exercised.
func dumpResolver(r *Resolver) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var b strings.Builder
	for _, fs := range r.fetches {
		b.WriteString(sprintfPlus(fs))
		for _, vs := range fs.values {
			b.WriteString(sprintfPlus(vs))
		}
	}
	return b.String()
}

// syncBuffer is a goroutine-safe bytes.Buffer for capturing log output from
// background loops.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}
