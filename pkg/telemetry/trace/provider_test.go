package trace_test

import (
	"crypto/rand"
	"encoding/base64"
	"runtime"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	oteltrace "go.opentelemetry.io/otel/trace"

	"github.com/pomerium/pomerium/pkg/telemetry/trace"
)

func benchmarkByCardinality(b *testing.B, n int, tracer oteltrace.Tracer) {
	b.Helper()
	ctx := b.Context()
	runtime.GC()
	start := &runtime.MemStats{}
	runtime.ReadMemStats(start)
	attrs := make([]string, n)

	for i := range n {
		attr := [8]byte{}
		_, _ = rand.Read(attr[:])
		attrStr := base64.RawURLEncoding.EncodeToString(attr[:])
		attrs[i] = attrStr
	}
	numSamples := uint64(0)
	for b.Loop() {
		_, span := tracer.Start(ctx, "foo.bar")
		defer span.End()
		for i := range n {
			span.SetAttributes(attribute.String(
				attrs[i],
				uuid.New().String(),
			))
		}
		numSamples++
	}
	runtime.GC()
	end := runtime.MemStats{}
	runtime.ReadMemStats(&end)
	b.Log("samples collected |cardinality | heap allocated | heap in use | heap objects| total frees")
	b.Logf(
		"%d | %d | %d | %d | %d | %d ",
		numSamples,
		n,
		end.HeapAlloc-start.HeapAlloc,
		end.HeapInuse-start.HeapInuse,
		end.HeapObjects-start.HeapObjects,
		end.Frees-start.Frees,
	)
	b.Logf("ratio (in use / samples) : %f", float64(end.HeapInuse-start.HeapInuse)/float64(numSamples))
}

func BenchmarkCardinality(b *testing.B) {
	opts := trace.Options{}
	ctx := opts.NewContext(b.Context(), trace.NoopClient{})
	provider := trace.NewTracerProvider(ctx, "test")

	tracer := provider.Tracer("foo")
	start := &runtime.MemStats{}
	runtime.ReadMemStats(start)

	b.Run("none", func(b *testing.B) {
		benchmarkByCardinality(b, 0, tracer)
		require.NoError(b, trace.ForceFlush(ctx))
	})

	b.Run("2", func(b *testing.B) {
		benchmarkByCardinality(b, 2, tracer)
		require.NoError(b, trace.ForceFlush(ctx))
	})

	b.Run("8", func(b *testing.B) {
		benchmarkByCardinality(b, 8, tracer)
		require.NoError(b, trace.ForceFlush(ctx))
	})

	b.Run("16", func(b *testing.B) {
		benchmarkByCardinality(b, 16, tracer)
		require.NoError(b, trace.ForceFlush(ctx))
	})
}
