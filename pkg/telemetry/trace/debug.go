package trace

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"iter"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	oteltrace "go.opentelemetry.io/otel/trace"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/encoding/protojson"
)

type DebugFlags uint32

const (
	// If set, adds the "caller" attribute to each trace with the source location
	// where the trace was started.
	TrackSpanCallers = (1 << iota)

	// If set, keeps track of all span references and will attempt to wait for
	// all traces to complete when shutting down a trace context.
	// Use with caution, this will cause increasing memory usage over time.
	TrackSpanReferences = (1 << iota)

	// If set, keeps track of all observed spans, including span context and
	// all attributes.
	// Use with caution, this will cause significantly increasing memory usage
	// over time.
	TrackAllSpans = (1 << iota) | TrackSpanCallers

	// If set, will log all trace IDs and their span counts on close.
	//
	// Enables [TrackAllSpans]
	LogTraceIDs = (1 << iota) | TrackAllSpans

	// If set, will log all spans observed by the exporter on close. These spans
	// may belong to incomplete traces.
	//
	// Enables [TrackAllSpans]
	LogAllSpans = (1 << iota) | TrackAllSpans

	// If set, will log all exported spans when a warning is issued on close
	// (requires warning flags to also be set)
	//
	// Enables [TrackAllSpans]
	LogAllSpansOnWarn = (1 << iota) | TrackAllSpans

	// If set, will log all trace ID mappings when a warning is issued on close.
	// (requires warning flags to also be set)
	LogTraceIDsOnWarn = (1 << iota)

	// If set, will print a warning to stderr on close if there are any incomplete
	// traces (traces with no observed root spans)
	WarnOnIncompleteTraces = (1 << iota)

	// If set, will print a warning to stderr on close if there are any incomplete
	// spans (spans started, but not ended)
	WarnOnIncompleteSpans = (1 << iota)

	// If set, will print a warning to stderr on close if there are any spans
	// which reference unknown parent spans.
	//
	// Enables [TrackSpanReferences]
	WarnOnUnresolvedReferences = (1 << iota) | TrackSpanReferences

	// If set, configures Envoy to flush every span individually, disabling its
	// internal buffer.
	EnvoyFlushEverySpan = (1 << iota)
)

func (df DebugFlags) Check(flags DebugFlags) bool {
	return (df & flags) == flags
}

var (
	ErrIncompleteSpans    = errors.New("exporter shut down with incomplete spans")
	ErrMissingParentSpans = errors.New("exporter shut down with missing parent spans")
)

// WaitForSpans will block up to the given max duration and wait for all
// in-flight spans from tracers created with the given context to end. This
// function can be called more than once, and is safe to call from multiple
// goroutines in parallel.
//
// This requires the [TrackSpanReferences] debug flag to have been set with
// [Options.NewContext]. Otherwise, this function is a no-op and will return
// immediately.
//
// If this function blocks for more than 10 seconds, it will print a warning
// to stderr containing a list of span IDs it is waiting for, and the IDs of
// their parents (if known). Additionally, if the [TrackAllSpans] debug flag
// is set, details about parent spans will be displayed, including call site
// and trace ID.
func WaitForSpans(ctx context.Context, maxDuration time.Duration) error {
	if sys := systemContextFromContext(ctx); sys != nil && sys.observer != nil {
		done := make(chan struct{})
		go func() {
			defer close(done)
			sys.observer.wait(10 * time.Second)
		}()
		select {
		case <-done:
			return nil
		case <-time.After(maxDuration):
			return ErrMissingParentSpans
		}
	}
	return nil
}

func DebugFlagsFromContext(ctx context.Context) DebugFlags {
	if sys := systemContextFromContext(ctx); sys != nil {
		return sys.options.DebugFlags
	}
	return 0
}

type stackTraceProcessor struct{}

// ForceFlush implements trace.SpanProcessor.
func (s *stackTraceProcessor) ForceFlush(context.Context) error {
	return nil
}

// OnEnd implements trace.SpanProcessor.
func (*stackTraceProcessor) OnEnd(sdktrace.ReadOnlySpan) {
}

// OnStart implements trace.SpanProcessor.
func (*stackTraceProcessor) OnStart(_ context.Context, s sdktrace.ReadWriteSpan) {
	_, file, line, _ := runtime.Caller(2)
	s.SetAttributes(attribute.String("caller", fmt.Sprintf("%s:%d", file, line)))
}

// Shutdown implements trace.SpanProcessor.
func (s *stackTraceProcessor) Shutdown(context.Context) error {
	return nil
}

var debugMessageWriter io.Writer

func startMsg(title string) *strings.Builder {
	msg := &strings.Builder{}
	msg.WriteString("\n==================================================\n")
	msg.WriteString(title)
	return msg
}

func endMsg(msg *strings.Builder) {
	msg.WriteString("==================================================\n")
	w := debugMessageWriter
	if w == nil {
		w = os.Stderr
	}
	fmt.Fprint(w, msg.String())
}

type DebugEvent struct {
	Timestamp time.Time                             `json:"timestamp"`
	Request   *coltracepb.ExportTraceServiceRequest `json:"request"`
}

func (e DebugEvent) MarshalJSON() ([]byte, error) {
	type debugEvent struct {
		Timestamp time.Time       `json:"timestamp"`
		Request   json.RawMessage `json:"request"`
	}
	reqData, _ := protojson.Marshal(e.Request)
	return json.Marshal(debugEvent{
		Timestamp: e.Timestamp,
		Request:   reqData,
	})
}

func (e *DebugEvent) UnmarshalJSON(b []byte) error {
	type debugEvent struct {
		Timestamp time.Time       `json:"timestamp"`
		Request   json.RawMessage `json:"request"`
	}
	var ev debugEvent
	if err := json.Unmarshal(b, &ev); err != nil {
		return err
	}
	e.Timestamp = ev.Timestamp
	var msg coltracepb.ExportTraceServiceRequest
	if err := protojson.Unmarshal(ev.Request, &msg); err != nil {
		return err
	}
	e.Request = &msg
	return nil
}

const shardCount = 64

type (
	shardedSet   [shardCount]map[oteltrace.SpanID]struct{}
	shardedLocks [shardCount]sync.Mutex
)

func (s *shardedSet) Range(f func(key oteltrace.SpanID)) {
	for i := range shardCount {
		for k := range s[i] {
			f(k)
		}
	}
}

func (s *shardedLocks) LockAll() {
	for i := range shardCount {
		s[i].Lock()
	}
}

func (s *shardedLocks) UnlockAll() {
	for i := range shardCount {
		s[i].Unlock()
	}
}

type spanTracker struct {
	inflightSpansMu   shardedLocks
	inflightSpans     shardedSet
	inflightSpanCount atomic.Int64
	allSpans          sync.Map
	debugFlags        DebugFlags
	observer          *spanObserver
	shutdownOnce      sync.Once
}

func newSpanTracker(observer *spanObserver, debugFlags DebugFlags) *spanTracker {
	st := &spanTracker{
		observer:   observer,
		debugFlags: debugFlags,
	}
	for i := range len(st.inflightSpans) {
		st.inflightSpans[i] = make(map[oteltrace.SpanID]struct{})
	}
	return st
}

type spanInfo struct {
	Name        string
	SpanContext oteltrace.SpanContext
	Parent      oteltrace.SpanContext
	caller      string
	startTime   time.Time
}

// ForceFlush implements trace.SpanProcessor.
func (t *spanTracker) ForceFlush(context.Context) error {
	return nil
}

// OnEnd implements trace.SpanProcessor.
func (t *spanTracker) OnEnd(s sdktrace.ReadOnlySpan) {
	id := s.SpanContext().SpanID()
	bucket := binary.BigEndian.Uint64(id[:]) % shardCount
	t.inflightSpansMu[bucket].Lock()
	defer t.inflightSpansMu[bucket].Unlock()
	delete(t.inflightSpans[bucket], id)
	t.inflightSpanCount.Add(-1)
}

// OnStart implements trace.SpanProcessor.
func (t *spanTracker) OnStart(_ context.Context, s sdktrace.ReadWriteSpan) {
	id := s.SpanContext().SpanID()
	bucket := binary.BigEndian.Uint64(id[:]) % shardCount
	t.inflightSpansMu[bucket].Lock()
	defer t.inflightSpansMu[bucket].Unlock()
	t.inflightSpans[bucket][id] = struct{}{}
	t.inflightSpanCount.Add(1)

	if t.debugFlags.Check(TrackSpanReferences) {
		if s.Parent().IsValid() {
			t.observer.ObserveReference(s.Parent().SpanID(), id)
		}
		t.observer.Observe(id)
	}

	if t.debugFlags.Check(TrackAllSpans) {
		var caller string
		for _, attr := range s.Attributes() {
			if attr.Key == "caller" {
				caller = attr.Value.AsString()
				break
			}
		}
		t.allSpans.Store(id, &spanInfo{
			Name:        s.Name(),
			SpanContext: s.SpanContext(),
			Parent:      s.Parent(),
			caller:      caller,
			startTime:   s.StartTime(),
		})
	}
}

// ShutdownGracePeriod sets the maximum duration to wait for in-flight spans to
// be completed during shutdown.
// Only has an effect when the WarnOnIncompleteSpans debug flag is enabled.
var ShutdownGracePeriod = 2 * time.Second

// Shutdown implements trace.SpanProcessor.
func (t *spanTracker) Shutdown(_ context.Context) error {
	if t.debugFlags == 0 {
		return nil
	}
	didWarn := false
	t.shutdownOnce.Do(func() {
		if t.debugFlags.Check(WarnOnUnresolvedReferences) {
			var unknownParentIDs []string
			for id, via := range t.observer.allReferencedIDs() {
				if via.IsValid() {
					if t.debugFlags.Check(TrackAllSpans) {
						if viaSpan, ok := t.allSpans.Load(via); ok {
							unknownParentIDs = append(unknownParentIDs, fmt.Sprintf("%s via %s (%s)", id, via, viaSpan.(*spanInfo).Name))
						} else {
							unknownParentIDs = append(unknownParentIDs, fmt.Sprintf("%s via %s", id, via))
						}
					}
				}
			}
			if len(unknownParentIDs) > 0 {
				didWarn = true
				msg := startMsg("WARNING: parent spans referenced but never seen:\n")
				for _, str := range unknownParentIDs {
					msg.WriteString(str)
					msg.WriteString("\n")
				}
				endMsg(msg)
			}
		}
		if t.debugFlags.Check(WarnOnIncompleteSpans) {
			inflightCount := t.inflightSpanCount.Load()
			if inflightCount > 0 && ShutdownGracePeriod > 0 {
				endMsg(startMsg(fmt.Sprintf("Waiting up to %s for %d in-flight spans to complete\n", ShutdownGracePeriod.String(), inflightCount)))
				pollInterval := 100 * time.Millisecond
				start := time.Now()
				for {
					time.Sleep(pollInterval)
					count := t.inflightSpanCount.Load()
					if count == 0 {
						endMsg(startMsg(fmt.Sprintf("All spans completed successfully in %s\n", time.Since(start).Round(pollInterval))))
						break
					}
					if time.Since(start) >= ShutdownGracePeriod {
						endMsg(startMsg(fmt.Sprintf("Timed out: %d/%d spans completed within the grace period\n", inflightCount-count, inflightCount)))
						break
					}
				}
			}
			if t.debugFlags.Check(TrackAllSpans) {
				incompleteSpans := []*spanInfo{}
				t.inflightSpansMu.LockAll()
				t.inflightSpans.Range(func(key oteltrace.SpanID) {
					if info, ok := t.allSpans.Load(key); ok {
						incompleteSpans = append(incompleteSpans, info.(*spanInfo))
					}
				})
				t.inflightSpansMu.UnlockAll()
				if len(incompleteSpans) > 0 {
					didWarn = true
					msg := startMsg("WARNING: spans not ended:\n")
					longestName := 0
					for _, span := range incompleteSpans {
						longestName = max(longestName, len(span.Name)+2)
					}
					for _, span := range incompleteSpans {
						var startedAt string
						if span.caller != "" {
							startedAt = " | started at: " + span.caller
						}
						fmt.Fprintf(msg, "%-*s (trace: %s | span: %s | parent: %s%s)\n", longestName, "'"+span.Name+"'",
							span.SpanContext.TraceID(), span.SpanContext.SpanID(), span.Parent.SpanID(), startedAt)
					}
					endMsg(msg)
				}
			} else {
				incompleteSpans := []oteltrace.SpanID{}
				t.inflightSpansMu.LockAll()
				t.inflightSpans.Range(func(key oteltrace.SpanID) {
					incompleteSpans = append(incompleteSpans, key)
				})
				t.inflightSpansMu.UnlockAll()
				if len(incompleteSpans) > 0 {
					didWarn = true
					msg := startMsg("WARNING: spans not ended:\n")
					for _, span := range incompleteSpans {
						fmt.Fprintf(msg, "%s\n", span)
					}
					msg.WriteString("Note: set TrackAllSpans flag for more info\n")
					endMsg(msg)
				}
			}
		}

		if t.debugFlags.Check(LogAllSpans) || (t.debugFlags.Check(LogAllSpansOnWarn) && didWarn) {
			allSpans := []*spanInfo{}
			t.allSpans.Range(func(_, value any) bool {
				allSpans = append(allSpans, value.(*spanInfo))
				return true
			})
			slices.SortFunc(allSpans, func(a, b *spanInfo) int {
				return a.startTime.Compare(b.startTime)
			})
			msg := startMsg("All observed spans:\n")
			longestName := 0
			for _, span := range allSpans {
				longestName = max(longestName, len(span.Name)+2)
			}
			for _, span := range allSpans {
				var startedAt string
				if span.caller != "" {
					startedAt = " | started at: " + span.caller
				}
				fmt.Fprintf(msg, "%-*s (trace: %s | span: %s | parent: %s%s)\n", longestName, "'"+span.Name+"'",
					span.SpanContext.TraceID(), span.SpanContext.SpanID(), span.Parent.SpanID(), startedAt)
			}
			endMsg(msg)
		}

		if t.debugFlags.Check(LogTraceIDs) || (didWarn && t.debugFlags.Check(LogTraceIDsOnWarn)) {
			msg := startMsg("Known trace ids:\n")
			traceIDs := map[oteltrace.TraceID]int{}
			t.allSpans.Range(func(_, value any) bool {
				v := value.(*spanInfo)
				traceIDs[v.SpanContext.TraceID()]++
				return true
			})
			for id, n := range traceIDs {
				fmt.Fprintf(msg, "%s (%d spans)\n", id.String(), n)
			}
			endMsg(msg)
		}
	})
	if didWarn {
		return ErrIncompleteSpans
	}
	return nil
}

func newSpanObserver() *spanObserver {
	return &spanObserver{
		referencedIDs: map[oteltrace.SpanID]oteltrace.SpanID{},
		cond:          sync.NewCond(&sync.Mutex{}),
	}
}

type spanObserver struct {
	cond          *sync.Cond
	referencedIDs map[oteltrace.SpanID]oteltrace.SpanID
	unobservedIDs int
}

func (obs *spanObserver) allReferencedIDs() iter.Seq2[oteltrace.SpanID, oteltrace.SpanID] {
	return func(yield func(k oteltrace.SpanID, v oteltrace.SpanID) bool) {
		obs.cond.L.Lock()
		defer obs.cond.L.Unlock()
		for k, v := range obs.referencedIDs {
			if !yield(k, v) {
				return
			}
		}
	}
}

func (obs *spanObserver) ObserveReference(id oteltrace.SpanID, via oteltrace.SpanID) {
	obs.cond.L.Lock()
	defer obs.cond.L.Unlock()
	if _, referenced := obs.referencedIDs[id]; !referenced {
		obs.referencedIDs[id] = via // referenced, but not observed
		// It is possible for new unobserved references to come in while waiting,
		// but incrementing the counter wouldn't satisfy the condition so we don't
		// need to signal the waiters
		obs.unobservedIDs++
	}
}

func (obs *spanObserver) Observe(id oteltrace.SpanID) {
	obs.cond.L.Lock()
	defer obs.cond.L.Unlock()
	if observed, referenced := obs.referencedIDs[id]; !referenced || observed.IsValid() { // NB: subtle condition
		obs.referencedIDs[id] = zeroSpanID
		if referenced {
			obs.unobservedIDs--
			obs.cond.Broadcast()
		}
	}
}

func (obs *spanObserver) wait(warnAfter time.Duration) {
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-done:
			return
		case <-time.After(warnAfter):
			obs.debugWarnWaiting()
		}
	}()

	obs.cond.L.Lock()
	for obs.unobservedIDs > 0 {
		obs.cond.Wait()
	}
	obs.cond.L.Unlock()
}

func (obs *spanObserver) debugWarnWaiting() {
	obs.cond.L.Lock()
	msg := startMsg(fmt.Sprintf("Waiting on %d unobserved spans:\n", obs.unobservedIDs))
	for id, via := range obs.referencedIDs {
		if via.IsValid() {
			fmt.Fprintf(msg, "%s via %s\n", id, via)
		}
	}
	endMsg(msg)
	obs.cond.L.Unlock()
}

func (srv *ExporterServer) observeExport(ctx context.Context, req *coltracepb.ExportTraceServiceRequest) {
	isLocal := len(metadata.ValueFromIncomingContext(ctx, localExporterMetadataKey)) != 0
	if isLocal {
		return
	}
	for _, res := range req.ResourceSpans {
		for _, scope := range res.ScopeSpans {
			for _, span := range scope.Spans {
				id, ok := ToSpanID(span.SpanId)
				if !ok {
					continue
				}
				srv.observer.Observe(id)
				for _, attr := range span.Attributes {
					if attr.Key != "pomerium.external-parent-span" {
						continue
					}
					if bytes, err := hex.DecodeString(attr.Value.GetStringValue()); err == nil {
						if id, ok := ToSpanID(bytes); ok {
							srv.observer.Observe(id)
						}
					}
					break
				}
			}
		}
	}
}
