package trace

import (
	"cmp"
	"io"
	"slices"
	"testing"
	"time"

	oteltrace "go.opentelemetry.io/otel/trace"
)

var (
	NewSpanObserver = newSpanObserver
	NewSpanTracker  = newSpanTracker
)

type XStackTraceProcessor = stackTraceProcessor

func (obs *spanObserver) XWait() {
	obs.wait(nil, 5*time.Second)
}

func (obs *spanObserver) XUnobservedIDs() []oteltrace.SpanID {
	obs.cond.L.Lock()
	defer obs.cond.L.Unlock()
	ids := []oteltrace.SpanID{}
	for k, v := range obs.referencedIDs {
		if v.IsValid() {
			ids = append(ids, k)
		}
	}
	slices.SortFunc(ids, func(a, b oteltrace.SpanID) int {
		return cmp.Compare(a.String(), b.String())
	})
	return ids
}

func (obs *spanObserver) XObservedIDs() []oteltrace.SpanID {
	obs.cond.L.Lock()
	defer obs.cond.L.Unlock()
	ids := []oteltrace.SpanID{}
	for k, v := range obs.referencedIDs {
		if !v.IsValid() {
			ids = append(ids, k)
		}
	}
	slices.SortFunc(ids, func(a, b oteltrace.SpanID) int {
		return cmp.Compare(a.String(), b.String())
	})
	return ids
}

func (t *spanTracker) XInflightSpans() []oteltrace.SpanID {
	ids := []oteltrace.SpanID{}
	t.inflightSpans.Range(func(key, _ any) bool {
		ids = append(ids, key.(oteltrace.SpanID))
		return true
	})
	slices.SortFunc(ids, func(a, b oteltrace.SpanID) int {
		return cmp.Compare(a.String(), b.String())
	})
	return ids
}

func SetDebugMessageWriterForTest(t testing.TB, w io.Writer) {
	debugMessageWriter = w
	t.Cleanup(func() {
		debugMessageWriter = nil
	})
}
