package trace_test

import (
	"bytes"
	"context"
	"fmt"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	. "github.com/pomerium/pomerium/internal/testutil/tracetest" //nolint:revive
	"github.com/pomerium/pomerium/pkg/telemetry/trace"
	"github.com/stretchr/testify/assert"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	oteltrace "go.opentelemetry.io/otel/trace"
)

func TestSpanObserver(t *testing.T) {
	t.Run("observe single reference", func(t *testing.T) {
		obs := trace.NewSpanObserver()
		assert.Equal(t, []oteltrace.SpanID{}, obs.XUnobservedIDs())

		obs.ObserveReference(Span(1).ID(), Span(2).ID())
		assert.Equal(t, []oteltrace.SpanID{Span(1).ID()}, obs.XUnobservedIDs())
		obs.Observe(Span(1).ID())
		assert.Equal(t, []oteltrace.SpanID{}, obs.XUnobservedIDs())
	})
	t.Run("observe multiple references", func(t *testing.T) {
		obs := trace.NewSpanObserver()

		obs.ObserveReference(Span(1).ID(), Span(2).ID())
		obs.ObserveReference(Span(1).ID(), Span(3).ID())
		obs.ObserveReference(Span(1).ID(), Span(4).ID())
		assert.Equal(t, []oteltrace.SpanID{Span(1).ID()}, obs.XUnobservedIDs())
		obs.Observe(Span(1).ID())
		assert.Equal(t, []oteltrace.SpanID{}, obs.XUnobservedIDs())
	})
	t.Run("observe before reference", func(t *testing.T) {
		obs := trace.NewSpanObserver()

		obs.Observe(Span(1).ID())
		assert.Equal(t, []oteltrace.SpanID{}, obs.XUnobservedIDs())
		obs.ObserveReference(Span(1).ID(), Span(2).ID())
		assert.Equal(t, []oteltrace.SpanID{}, obs.XUnobservedIDs())
	})

	t.Run("wait", func(t *testing.T) {
		obs := trace.NewSpanObserver()
		obs.ObserveReference(Span(1).ID(), Span(2).ID())
		obs.Observe(Span(2).ID())
		obs.ObserveReference(Span(3).ID(), Span(4).ID())
		obs.Observe(Span(4).ID())
		obs.ObserveReference(Span(5).ID(), Span(6).ID())
		obs.Observe(Span(6).ID())
		waitOkToExit := atomic.Bool{}
		waitExited := atomic.Bool{}
		go func() {
			defer waitExited.Store(true)
			obs.XWait()
			assert.True(t, waitOkToExit.Load(), "wait exited early")
		}()

		time.Sleep(10 * time.Millisecond)
		assert.False(t, waitExited.Load())

		obs.Observe(Span(1).ID())
		time.Sleep(10 * time.Millisecond)
		assert.False(t, waitExited.Load())

		obs.Observe(Span(3).ID())
		time.Sleep(10 * time.Millisecond)
		assert.False(t, waitExited.Load())

		waitOkToExit.Store(true)
		obs.Observe(Span(5).ID())
		assert.Eventually(t, waitExited.Load, 10*time.Millisecond, 1*time.Millisecond)
	})

	t.Run("new references observed during wait", func(t *testing.T) {
		obs := trace.NewSpanObserver()
		obs.ObserveReference(Span(1).ID(), Span(2).ID())
		obs.Observe(Span(2).ID())
		obs.ObserveReference(Span(3).ID(), Span(4).ID())
		obs.Observe(Span(4).ID())
		obs.ObserveReference(Span(5).ID(), Span(6).ID())
		obs.Observe(Span(6).ID())
		waitOkToExit := atomic.Bool{}
		waitExited := atomic.Bool{}
		go func() {
			defer waitExited.Store(true)
			obs.XWait()
			assert.True(t, waitOkToExit.Load(), "wait exited early")
		}()

		assert.Equal(t, []oteltrace.SpanID{Span(1).ID(), Span(3).ID(), Span(5).ID()}, obs.XUnobservedIDs())
		time.Sleep(10 * time.Millisecond)
		assert.False(t, waitExited.Load())

		obs.Observe(Span(1).ID())
		assert.Equal(t, []oteltrace.SpanID{Span(3).ID(), Span(5).ID()}, obs.XUnobservedIDs())
		time.Sleep(10 * time.Millisecond)
		assert.False(t, waitExited.Load())

		obs.Observe(Span(3).ID())
		assert.Equal(t, []oteltrace.SpanID{Span(5).ID()}, obs.XUnobservedIDs())
		time.Sleep(10 * time.Millisecond)
		assert.False(t, waitExited.Load())

		// observe a new reference
		obs.ObserveReference(Span(7).ID(), Span(8).ID())
		obs.Observe(Span(8).ID())
		assert.Equal(t, []oteltrace.SpanID{Span(5).ID(), Span(7).ID()}, obs.XUnobservedIDs())
		time.Sleep(10 * time.Millisecond)
		assert.False(t, waitExited.Load())

		obs.Observe(Span(5).ID())
		assert.Equal(t, []oteltrace.SpanID{Span(7).ID()}, obs.XUnobservedIDs())
		time.Sleep(10 * time.Millisecond)
		assert.False(t, waitExited.Load())

		waitOkToExit.Store(true)
		obs.Observe(Span(7).ID())
		assert.Equal(t, []oteltrace.SpanID{}, obs.XUnobservedIDs())
		assert.Eventually(t, waitExited.Load, 10*time.Millisecond, 1*time.Millisecond)
	})

	t.Run("multiple waiters", func(t *testing.T) {
		t.Parallel()
		obs := trace.NewSpanObserver()
		obs.ObserveReference(Span(1).ID(), Span(2).ID())
		obs.Observe(Span(2).ID())

		waitersExited := atomic.Int32{}
		for range 10 {
			go func() {
				defer waitersExited.Add(1)
				obs.XWait()
			}()
		}

		assert.Equal(t, []oteltrace.SpanID{Span(1).ID()}, obs.XUnobservedIDs())
		time.Sleep(10 * time.Millisecond)
		assert.Equal(t, int32(0), waitersExited.Load())

		obs.Observe(Span(1).ID())

		assert.Eventually(t, func() bool {
			return waitersExited.Load() == 10
		}, 10*time.Millisecond, 1*time.Millisecond)
	})
}

func TestSpanTracker(t *testing.T) {
	t.Run("no debug flags", func(t *testing.T) {
		t.Parallel()
		obs := trace.NewSpanObserver()
		tracker := trace.NewSpanTracker(obs, 0)
		tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(tracker))
		tracer := tp.Tracer("test")
		assert.Equal(t, []oteltrace.SpanID{}, tracker.XInflightSpans())
		_, span1 := tracer.Start(context.Background(), "span 1")
		assert.Equal(t, []oteltrace.SpanID{span1.SpanContext().SpanID()}, tracker.XInflightSpans())
		assert.Equal(t, []oteltrace.SpanID{}, obs.XObservedIDs())
		span1.End()
		assert.Equal(t, []oteltrace.SpanID{}, tracker.XInflightSpans())
		assert.Equal(t, []oteltrace.SpanID{}, obs.XObservedIDs())
	})
	t.Run("with TrackSpanReferences debug flag", func(t *testing.T) {
		t.Parallel()
		obs := trace.NewSpanObserver()
		tracker := trace.NewSpanTracker(obs, trace.TrackSpanReferences)
		tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(tracker))
		tracer := tp.Tracer("test")
		assert.Equal(t, []oteltrace.SpanID{}, tracker.XInflightSpans())
		_, span1 := tracer.Start(context.Background(), "span 1")
		assert.Equal(t, []oteltrace.SpanID{span1.SpanContext().SpanID()}, tracker.XInflightSpans())
		assert.Equal(t, []oteltrace.SpanID{span1.SpanContext().SpanID()}, obs.XObservedIDs())
		span1.End()
		assert.Equal(t, []oteltrace.SpanID{}, tracker.XInflightSpans())
		assert.Equal(t, []oteltrace.SpanID{span1.SpanContext().SpanID()}, obs.XObservedIDs())
	})
}

func TestSpanTrackerWarnings(t *testing.T) {
	t.Run("WarnOnIncompleteSpans", func(t *testing.T) {
		var buf bytes.Buffer
		trace.SetDebugMessageWriterForTest(t, &buf)

		obs := trace.NewSpanObserver()
		tracker := trace.NewSpanTracker(obs, trace.WarnOnIncompleteSpans)
		tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(tracker))
		tracer := tp.Tracer("test")
		_, span1 := tracer.Start(context.Background(), "span 1")

		assert.ErrorIs(t, tp.Shutdown(context.Background()), trace.ErrIncompleteSpans)

		assert.Equal(t, fmt.Sprintf(`
==================================================
WARNING: spans not ended:
%s
Note: set TrackAllSpans flag for more info
==================================================
`, span1.SpanContext().SpanID()), buf.String())
	})

	t.Run("WarnOnIncompleteSpans with TrackAllSpans", func(t *testing.T) {
		var buf bytes.Buffer
		trace.SetDebugMessageWriterForTest(t, &buf)

		obs := trace.NewSpanObserver()
		tracker := trace.NewSpanTracker(obs, trace.WarnOnIncompleteSpans|trace.TrackAllSpans)
		tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(tracker))
		tracer := tp.Tracer("test")
		_, span1 := tracer.Start(context.Background(), "span 1")

		assert.ErrorIs(t, tp.Shutdown(context.Background()), trace.ErrIncompleteSpans)

		assert.Equal(t, fmt.Sprintf(`
==================================================
WARNING: spans not ended:
'span 1' (trace: %s | span: %s | parent: 0000000000000000)
==================================================
`, span1.SpanContext().TraceID(), span1.SpanContext().SpanID()), buf.String())
	})

	t.Run("WarnOnIncompleteSpans with TrackAllSpans and stackTraceProcessor", func(t *testing.T) {
		var buf bytes.Buffer
		trace.SetDebugMessageWriterForTest(t, &buf)

		obs := trace.NewSpanObserver()
		tracker := trace.NewSpanTracker(obs, trace.WarnOnIncompleteSpans|trace.TrackAllSpans)
		tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(&trace.XStackTraceProcessor{}), sdktrace.WithSpanProcessor(tracker))
		tracer := tp.Tracer("test")
		_, span1 := tracer.Start(context.Background(), "span 1")
		_, file, line, _ := runtime.Caller(0)
		line--

		assert.ErrorIs(t, tp.Shutdown(context.Background()), trace.ErrIncompleteSpans)

		assert.Equal(t, fmt.Sprintf(`
==================================================
WARNING: spans not ended:
'span 1' (trace: %s | span: %s | parent: 0000000000000000 | started at: %s:%d)
==================================================
`, span1.SpanContext().TraceID(), span1.SpanContext().SpanID(), file, line), buf.String())
	})

	t.Run("LogAllSpansOnWarn", func(t *testing.T) {
		var buf bytes.Buffer
		trace.SetDebugMessageWriterForTest(t, &buf)

		obs := trace.NewSpanObserver()
		tracker := trace.NewSpanTracker(obs, trace.WarnOnIncompleteSpans|trace.TrackAllSpans|trace.LogAllSpansOnWarn)
		tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(&trace.XStackTraceProcessor{}), sdktrace.WithSpanProcessor(tracker))
		tracer := tp.Tracer("test")
		_, span1 := tracer.Start(context.Background(), "span 1")
		time.Sleep(10 * time.Millisecond)
		span1.End()
		time.Sleep(10 * time.Millisecond)
		_, span2 := tracer.Start(context.Background(), "span 2")
		_, file, line, _ := runtime.Caller(0)
		line--

		tp.Shutdown(context.Background())

		assert.Equal(t,
			fmt.Sprintf(`
==================================================
WARNING: spans not ended:
'span 2' (trace: %[1]s | span: %[2]s | parent: 0000000000000000 | started at: %[3]s:%[4]d)
==================================================

==================================================
All observed spans:
'span 1' (trace: %[5]s | span: %[6]s | parent: 0000000000000000 | started at: %[3]s:%[7]d)
'span 2' (trace: %[1]s | span: %[2]s | parent: 0000000000000000 | started at: %[3]s:%[4]d)
==================================================
`,
				span2.SpanContext().TraceID(), span2.SpanContext().SpanID(), file, line,
				span1.SpanContext().TraceID(), span1.SpanContext().SpanID(), line-4,
			), buf.String())
	})
}
