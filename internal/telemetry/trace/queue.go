package trace

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
	"unique"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	oteltrace "go.opentelemetry.io/otel/trace"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	tracev1 "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

var (
	maxPendingTraces  atomic.Int32
	maxCachedTraceIDs atomic.Int32
)

func init() {
	envOrDefault := func(envName string, def int32) int32 {
		if val, ok := os.LookupEnv(envName); ok {
			if num, err := strconv.ParseInt(val, 10, 32); err == nil {
				return int32(num)
			}
		}
		return def
	}
	maxPendingTraces.Store(envOrDefault("POMERIUM_OTEL_MAX_PENDING_TRACES", 8192))
	maxCachedTraceIDs.Store(envOrDefault("POMERIUM_OTEL_MAX_CACHED_TRACE_IDS", 16384))
}

func SetMaxPendingTraces(num int32) {
	maxPendingTraces.Store(max(num, 0))
}

func SetMaxCachedTraceIDs(num int32) {
	maxCachedTraceIDs.Store(max(num, 0))
}

type eviction struct {
	traceID unique.Handle[oteltrace.TraceID]
	buf     *Buffer
}

type SpanExportQueue struct {
	closing                   chan struct{}
	uploadC                   chan []*tracev1.ResourceSpans
	requestC                  chan *coltracepb.ExportTraceServiceRequest
	evictC                    chan eviction
	client                    otlptrace.Client
	pendingResourcesByTraceID *lru.Cache[unique.Handle[oteltrace.TraceID], *Buffer]
	knownTraceIDMappings      *lru.Cache[unique.Handle[oteltrace.TraceID], unique.Handle[oteltrace.TraceID]]
	tracker                   *spanTracker
	observer                  *spanObserver
	debugEvents               []DebugEvent
	logger                    *zerolog.Logger
	debugFlags                DebugFlags
	debugAllEnqueuedSpans     map[oteltrace.SpanID]*tracev1.Span
	wg                        sync.WaitGroup
}

func NewSpanExportQueue(ctx context.Context, client otlptrace.Client) *SpanExportQueue {
	debug := DebugFlagsFromContext(ctx)
	var observer *spanObserver
	if debug.Check(TrackSpanReferences) {
		observer = newSpanObserver()
	}
	q := &SpanExportQueue{
		logger:                log.Ctx(ctx),
		client:                client,
		closing:               make(chan struct{}),
		uploadC:               make(chan []*tracev1.ResourceSpans, 64),
		requestC:              make(chan *coltracepb.ExportTraceServiceRequest, 256),
		evictC:                make(chan eviction, 64),
		debugFlags:            debug,
		debugAllEnqueuedSpans: make(map[oteltrace.SpanID]*tracev1.Span),
		tracker:               newSpanTracker(observer, debug),
		observer:              observer,
	}
	var err error
	q.pendingResourcesByTraceID, err = lru.NewWithEvict(int(maxPendingTraces.Load()), q.onEvict)
	if err != nil {
		panic(err)
	}
	q.knownTraceIDMappings, err = lru.New[unique.Handle[oteltrace.TraceID], unique.Handle[oteltrace.TraceID]](int(maxCachedTraceIDs.Load()))
	if err != nil {
		panic(err)
	}
	q.wg.Add(2)
	go q.runUploader()
	go q.runProcessor()
	return q
}

func (q *SpanExportQueue) runUploader() {
	defer q.wg.Done()
	for resourceSpans := range q.uploadC {
		ctx, ca := context.WithTimeout(context.Background(), 10*time.Second)
		if err := q.client.UploadTraces(ctx, resourceSpans); err != nil {
			q.logger.Err(err).Msg("error uploading traces")
		}
		ca()
	}
}

func (q *SpanExportQueue) runProcessor() {
	defer q.wg.Done()
	for {
		select {
		case req := <-q.requestC:
			q.processRequestLocked(req)
		case ev := <-q.evictC:
			q.processEvictionLocked(ev)
		case <-q.closing:
			for {
				select {
				case req := <-q.requestC:
					q.processRequestLocked(req)
				case ev := <-q.evictC:
					q.processEvictionLocked(ev)
				default: // all channels empty
					close(q.uploadC)
					return
				}
			}
		}
	}
}

func (q *SpanExportQueue) onEvict(traceID unique.Handle[oteltrace.TraceID], buf *Buffer) {
	q.evictC <- eviction{
		traceID: traceID,
		buf:     buf,
	}
}

func (q *SpanExportQueue) insertPendingSpanLocked(
	resource *ResourceInfo,
	scope *ScopeInfo,
	traceID unique.Handle[oteltrace.TraceID],
	span *tracev1.Span,
) {
	var pendingTraceResources *Buffer

	if ptr, ok := q.pendingResourcesByTraceID.Get(traceID); ok {
		pendingTraceResources = ptr
	} else {
		pendingTraceResources = NewBuffer()
		q.pendingResourcesByTraceID.Add(traceID, pendingTraceResources)
	}
	pendingTraceResources.Insert(resource, scope, span)
}

func (q *SpanExportQueue) resolveTraceIDMappingLocked(out *Buffer, original, target unique.Handle[oteltrace.TraceID]) {
	q.knownTraceIDMappings.Add(original, target)

	if target == zeroTraceID && original != zeroTraceID {
		// mapping a trace id to zero indicates we should drop the trace
		q.pendingResourcesByTraceID.Remove(original)
		return
	}

	if originalPending, ok := q.pendingResourcesByTraceID.Peek(original); ok {
		if original == target {
			out.Merge(originalPending)
		} else {
			// check if the target id is also pending
			if targetPending, ok := q.pendingResourcesByTraceID.Peek(target); ok {
				targetPending.MergeAs(originalPending, target)
			} else {
				out.MergeAs(originalPending, target)
			}
		}
		q.pendingResourcesByTraceID.Remove(original)
	}
}

func (q *SpanExportQueue) getTraceIDMappingLocked(id unique.Handle[oteltrace.TraceID]) (unique.Handle[oteltrace.TraceID], bool) {
	v, ok := q.knownTraceIDMappings.Get(id)
	return v, ok
}

func (q *SpanExportQueue) isKnownTracePendingLocked(id unique.Handle[oteltrace.TraceID]) bool {
	_, ok := q.pendingResourcesByTraceID.Get(id) // will update the key's recent-ness in the lru
	return ok
}

var ErrShuttingDown = errors.New("exporter is shutting down")

func (q *SpanExportQueue) Enqueue(_ context.Context, req *coltracepb.ExportTraceServiceRequest) error {
	select {
	case <-q.closing:
		return ErrShuttingDown
	default:
		q.requestC <- req
		return nil
	}
}

func (q *SpanExportQueue) processRequestLocked(req *coltracepb.ExportTraceServiceRequest) {
	if q.debugFlags.Check(LogAllEvents) {
		q.debugEvents = append(q.debugEvents, DebugEvent{
			Timestamp: time.Now(),
			Request:   proto.Clone(req).(*coltracepb.ExportTraceServiceRequest),
		})
	}

	// Spans are processed in two passes:
	// 1. Look through each span to check if we have not yet seen its trace ID.
	//    If we haven't, and the span is a root span (no parent, or marked as such
	//    by us), mark the trace as observed, and (if indicated) keep track of the
	//    trace ID we need to rewrite it as, so that other spans we see later in
	//    this trace can also be rewritten the same way.
	//    If we find a new trace ID for which there are pending non-root spans,
	//    collect them and rewrite their trace IDs (if necessary), and prepare
	//    them to be uploaded.
	//
	// At this point, all trace IDs for the spans in the request are known.
	//
	// 2. Look through each span again, this time to filter out any spans in
	//    the request which belong to "pending" traces (known trace IDs for which
	//    we have not yet seen a root span), adding them to the list of pending
	//    spans for their corresponding trace IDs. They will be uploaded in the
	//    future once we have observed a root span for those traces, or if they
	//    are evicted by the queue.

	// Pass 1
	toUpload := NewBuffer()
	for _, resource := range req.ResourceSpans {
		for _, scope := range resource.ScopeSpans {
		SPANS:
			for _, span := range scope.Spans {
				FormatSpanName(span)
				spanID, ok := ToSpanID(span.SpanId)
				if !ok {
					continue
				}
				if q.debugFlags.Check(TrackAllSpans) {
					q.debugAllEnqueuedSpans[spanID] = span
				}
				trackSpanReferences := q.debugFlags.Check(TrackSpanReferences)
				parentSpanID, ok := ToSpanID(span.ParentSpanId)
				if !ok {
					continue
				}
				traceID, ok := ToTraceID(span.TraceId)
				if !ok {
					continue
				}
				if trackSpanReferences {
					q.observer.Observe(spanID)
				}
				if mapping, ok := q.getTraceIDMappingLocked(traceID); ok {
					if trackSpanReferences && mapping != zeroTraceID && parentSpanID.IsValid() {
						q.observer.ObserveReference(parentSpanID, spanID)
					}
				} else {
					// Observed a new trace ID. Check if the span is a root span
					isRootSpan := !parentSpanID.IsValid() // no parent == root span

					// Assume the trace is sampled, because it was exported. span.Flags
					// is an unreliable way to detect whether the span was sampled,
					// because neither envoy nor opentelemetry-go encode the sampling
					// decision there, assuming unsampled spans would not be exported
					// (this was not taking into account tail-based sampling strategies)
					// https://github.com/open-telemetry/opentelemetry-proto/issues/166
					isSampled := true

					mappedTraceID := traceID
					for _, attr := range span.Attributes {
						switch attr.Key {
						case "pomerium.traceparent":
							tp, err := ParseTraceparent(attr.GetValue().GetStringValue())
							if err != nil {
								data, _ := protojson.Marshal(span)
								q.logger.
									Err(err).
									Str("span", string(data)).
									Msg("error processing span")
								continue SPANS
							}
							mappedTraceID = unique.Make(tp.TraceID())
							// use the sampling decision from pomerium.traceparent instead
							isSampled = tp.IsSampled()
						case "pomerium.external-parent-span":
							// This is a non-root span whose parent we do not expect to see
							// here. For example, if a request originated externally from a
							// system that is uploading its own spans out-of-band from us,
							// we will never observe a root span for this trace and it would
							// otherwise get stuck in the queue.
							if !isRootSpan && q.debugFlags.Check(TrackSpanReferences) {
								value, err := oteltrace.SpanIDFromHex(attr.GetValue().GetStringValue())
								if err != nil {
									data, _ := protojson.Marshal(span)
									q.logger.
										Err(err).
										Str("span", string(data)).
										Msg("error processing span: invalid value for pomerium.external-parent-span")
								} else {
									q.observer.Observe(value) // mark this id as observed
								}
							}
							isRootSpan = true
						}
					}

					if q.debugFlags.Check(TrackSpanReferences) {
						if isSampled && parentSpanID.IsValid() {
							q.observer.ObserveReference(parentSpanID, spanID)
						}
					}

					if !isSampled {
						// We have observed a new trace that is not sampled (regardless of
						// whether or not it is a root span). Resolve it using the zero
						// trace ID to indicate that all spans for this trace should be
						// dropped.
						q.resolveTraceIDMappingLocked(toUpload, traceID, zeroTraceID)
					} else if isRootSpan {
						// We have observed a new trace that is sampled and is a root span.
						// Resolve it using the mapped trace ID (if present), or its own
						// trace ID (indicating it does not need to be rewritten).
						// If the mapped trace is pending, this does not flush pending
						// spans to the output buffer (toUpload), but instead merges them
						// into the mapped trace's pending buffer.
						q.resolveTraceIDMappingLocked(toUpload, traceID, mappedTraceID)
					}
				}
			}
		}
	}

	// Pass 2
	for _, resource := range req.ResourceSpans {
		resourceInfo := NewResourceInfo(resource.Resource, resource.SchemaUrl)
		for _, scope := range resource.ScopeSpans {
			scopeInfo := NewScopeInfo(scope.Scope, scope.SchemaUrl)
			for _, span := range scope.Spans {
				traceID, ok := ToTraceID(span.TraceId)
				if !ok {
					continue
				}

				if mapping, hasMapping := q.getTraceIDMappingLocked(traceID); hasMapping {
					if mapping == zeroTraceID {
						continue // the trace has been dropped
					}
					id := mapping.Value()
					copy(span.TraceId, id[:])
					// traceID = mapping
					if q.isKnownTracePendingLocked(mapping) {
						q.insertPendingSpanLocked(resourceInfo, scopeInfo, mapping, span)
					} else {
						toUpload.Insert(resourceInfo, scopeInfo, span)
					}
				} else {
					q.insertPendingSpanLocked(resourceInfo, scopeInfo, traceID, span)
				}
			}
		}
	}
	if resourceSpans := toUpload.Flush(); len(resourceSpans) > 0 {
		q.uploadC <- resourceSpans
	}
}

func (q *SpanExportQueue) processEvictionLocked(ev eviction) {
	if ev.buf.IsEmpty() {
		// if the buffer is not empty, it was evicted automatically
		return
	} else if mapping, ok := q.knownTraceIDMappings.Get(ev.traceID); ok && mapping == zeroTraceID {
		q.logger.Debug().
			Str("traceID", ev.traceID.Value().String()).
			Msg("dropping unsampled trace")
		return
	}

	select {
	case q.uploadC <- ev.buf.Flush():
		q.logger.Warn().
			Str("traceID", ev.traceID.Value().String()).
			Msg("trace export buffer is full, uploading oldest incomplete trace")
	default:
		q.logger.Warn().
			Str("traceID", ev.traceID.Value().String()).
			Msg("trace export buffer and upload queues are full, dropping trace")
	}
}

var (
	ErrIncompleteTraces   = errors.New("exporter shut down with incomplete traces")
	ErrIncompleteSpans    = errors.New("exporter shut down with incomplete spans")
	ErrIncompleteUploads  = errors.New("exporter shut down with pending trace uploads")
	ErrMissingParentSpans = errors.New("exporter shut down with missing parent spans")
)

func (q *SpanExportQueue) WaitForSpans(maxDuration time.Duration) error {
	if !q.debugFlags.Check(TrackSpanReferences) {
		return nil
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		q.observer.wait(q.debugAllEnqueuedSpans, 10*time.Second)
	}()
	select {
	case <-done:
		return nil
	case <-time.After(maxDuration):
		return ErrMissingParentSpans
	}
}

func (q *SpanExportQueue) Close(ctx context.Context) error {
	closed := make(chan struct{})
	go func() {
		q.wg.Wait()
		close(closed)
	}()
	close(q.closing)
	select {
	case <-ctx.Done():
		log.Ctx(ctx).Error().Msg("exporter stopped before all traces could be exported")
		return context.Cause(ctx)
	case <-closed:
		err := q.runOnCloseChecksLocked()
		log.Ctx(ctx).Debug().Err(err).Msg("exporter stopped")
		return err
	}
}

func (q *SpanExportQueue) runOnCloseChecksLocked() error {
	didWarn := false
	if q.debugFlags.Check(TrackSpanReferences) {
		var unknownParentIDs []string
		for id, via := range q.observer.referencedIDs {
			if via.IsValid() {
				if q.debugFlags.Check(TrackAllSpans) {
					if viaSpan, ok := q.debugAllEnqueuedSpans[via]; ok {
						unknownParentIDs = append(unknownParentIDs, fmt.Sprintf("%s via %s (%s)", id, via, viaSpan.Name))
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
	incomplete := q.pendingResourcesByTraceID.Len() > 0
	if incomplete && q.debugFlags.Check(WarnOnIncompleteTraces) {
		didWarn = true
		msg := startMsg("WARNING: exporter shut down with incomplete traces\n")
		keys := q.pendingResourcesByTraceID.Keys()
		values := q.pendingResourcesByTraceID.Values()
		for i, k := range keys {
			v := values[i]
			fmt.Fprintf(msg, "- Trace: %s\n", k.Value())
			for _, pendingScope := range v.scopesByResourceID {
				msg.WriteString("  - Resource:\n")
				for _, v := range pendingScope.resource.Resource.Attributes {
					fmt.Fprintf(msg, "     %s=%s\n", v.Key, v.Value.String())
				}
				for _, spanBuffer := range pendingScope.spansByScope {
					if spanBuffer.scope != nil {
						fmt.Fprintf(msg, "    Scope: %s\n", spanBuffer.scope.ID())
					} else {
						msg.WriteString("    Scope: (unknown)\n")
					}
					msg.WriteString("    Spans:\n")
					longestName := 0
					for _, span := range spanBuffer.spans {
						longestName = max(longestName, len(span.Name)+2)
					}
					for _, span := range spanBuffer.spans {
						spanID, ok := ToSpanID(span.SpanId)
						if !ok {
							continue
						}
						traceID, ok := ToTraceID(span.TraceId)
						if !ok {
							continue
						}
						parentSpanID, ok := ToSpanID(span.ParentSpanId)
						if !ok {
							continue
						}
						_, seenParent := q.debugAllEnqueuedSpans[parentSpanID]
						var missing string
						if !seenParent {
							missing = " [missing]"
						}
						fmt.Fprintf(msg, "    - %-*s (trace: %s | span: %s | parent:%s %s)\n", longestName,
							"'"+span.Name+"'", traceID.Value(), spanID, missing, parentSpanID)
						for _, attr := range span.Attributes {
							if attr.Key == "caller" {
								fmt.Fprintf(msg, "      => caller: '%s'\n", attr.Value.GetStringValue())
								break
							}
						}
					}
				}
			}
		}
		endMsg(msg)
	}

	if q.debugFlags.Check(LogTraceIDMappings) || (didWarn && q.debugFlags.Check(LogTraceIDMappingsOnWarn)) {
		msg := startMsg("Known trace ids:\n")
		keys := q.knownTraceIDMappings.Keys()
		values := q.knownTraceIDMappings.Values()
		for i, k := range keys {
			v := values[i]
			if k != v {
				if v == zeroTraceID {
					fmt.Fprintf(msg, "%s (dropped)\n", k.Value())
				} else {
					fmt.Fprintf(msg, "%s => %s\n", k.Value(), v.Value())
				}
			} else {
				fmt.Fprintf(msg, "%s (no change)\n", k.Value())
			}
		}
		endMsg(msg)
	}
	if q.debugFlags.Check(LogAllSpans) || (didWarn && q.debugFlags.Check(LogAllSpansOnWarn)) {
		msg := startMsg("All exported spans:\n")
		longestName := 0
		for _, span := range q.debugAllEnqueuedSpans {
			longestName = max(longestName, len(span.Name)+2)
		}
		for _, span := range q.debugAllEnqueuedSpans {
			spanID, ok := ToSpanID(span.SpanId)
			if !ok {
				continue
			}
			traceID, ok := ToTraceID(span.TraceId)
			if !ok {
				continue
			}
			parentSpanID, ok := ToSpanID(span.ParentSpanId)
			if !ok {
				continue
			}
			fmt.Fprintf(msg, "%-*s (trace: %s | span: %s | parent: %s)", longestName,
				"'"+span.Name+"'", traceID.Value(), spanID, parentSpanID)
			var foundCaller bool
			for _, attr := range span.Attributes {
				if attr.Key == "caller" {
					fmt.Fprintf(msg, " => %s\n", attr.Value.GetStringValue())
					foundCaller = true
					break
				}
			}
			if !foundCaller {
				msg.WriteString("\n")
			}
		}
		endMsg(msg)
	}
	if q.debugFlags.Check(LogAllEvents) {
		msg := startMsg("All Events:\n")
		msg.WriteByte('[')
		for i, event := range q.debugEvents {
			msg.WriteString("\n  ")
			eventData, _ := json.Marshal(event)
			msg.Write(eventData)
			if i < len(q.debugEvents)-1 {
				msg.WriteByte(',')
			} else {
				msg.WriteString("\n]")
			}
		}
		msg.WriteByte('\n')
		endMsg(msg)
	}
	if incomplete {
		return ErrIncompleteTraces
	}
	return nil
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
	inflightSpansMu shardedLocks
	inflightSpans   shardedSet
	allSpans        sync.Map
	debugFlags      DebugFlags
	observer        *spanObserver
	shutdownOnce    sync.Once
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
}

// OnStart implements trace.SpanProcessor.
func (t *spanTracker) OnStart(_ context.Context, s sdktrace.ReadWriteSpan) {
	id := s.SpanContext().SpanID()
	bucket := binary.BigEndian.Uint64(id[:]) % shardCount
	t.inflightSpansMu[bucket].Lock()
	defer t.inflightSpansMu[bucket].Unlock()
	t.inflightSpans[bucket][id] = struct{}{}

	if t.debugFlags.Check(TrackSpanReferences) {
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

// Shutdown implements trace.SpanProcessor.
func (t *spanTracker) Shutdown(_ context.Context) error {
	if t.debugFlags == 0 {
		return nil
	}
	didWarn := false
	t.shutdownOnce.Do(func() {
		if t.debugFlags.Check(WarnOnIncompleteSpans) {
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

func (obs *spanObserver) wait(debugAllEnqueuedSpans map[oteltrace.SpanID]*tracev1.Span, warnAfter time.Duration) {
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-done:
			return
		case <-time.After(warnAfter):
			obs.debugWarnWaiting(debugAllEnqueuedSpans)
		}
	}()

	obs.cond.L.Lock()
	for obs.unobservedIDs > 0 {
		obs.cond.Wait()
	}
	obs.cond.L.Unlock()
}

func (obs *spanObserver) debugWarnWaiting(debugAllEnqueuedSpans map[oteltrace.SpanID]*tracev1.Span) {
	obs.cond.L.Lock()
	msg := startMsg(fmt.Sprintf("Waiting on %d unobserved spans:\n", obs.unobservedIDs))
	for id, via := range obs.referencedIDs {
		if via.IsValid() {
			fmt.Fprintf(msg, "%s via %s", id, via)
			if span := debugAllEnqueuedSpans[id]; span != nil {
				createdAt := "(unknown)"
				for _, attr := range span.Attributes {
					if attr.Key == "caller" {
						createdAt = attr.Value.GetStringValue()
						break
					}
				}
				fmt.Fprintf(msg, "'%s' (trace: %s | created: %s)\n", span.GetName(), span.TraceId, createdAt)
			} else {
				msg.WriteString("\n")
			}
		}
	}
	endMsg(msg)
	obs.cond.L.Unlock()
}
