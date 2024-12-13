package trace

import (
	"context"
	"errors"
	"fmt"
	"os"
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
	maxPendingTraces.Store(envOrDefault("POMERIUM_OTEL_MAX_PENDING_TRACES", 1024))
	maxCachedTraceIDs.Store(envOrDefault("POMERIUM_OTEL_MAX_CACHED_TRACE_IDS", 8192))
}

func SetMaxPendingTraces(num int32) {
	maxPendingTraces.Store(max(num, 0))
}

func SetMaxCachedTraceIDs(num int32) {
	maxCachedTraceIDs.Store(max(num, 0))
}

type SpanExportQueue struct {
	mu                        sync.Mutex
	logger                    *zerolog.Logger
	client                    otlptrace.Client
	pendingResourcesByTraceID *lru.Cache[unique.Handle[oteltrace.TraceID], *Buffer]
	knownTraceIDMappings      *lru.Cache[unique.Handle[oteltrace.TraceID], unique.Handle[oteltrace.TraceID]]
	uploadC                   chan []*tracev1.ResourceSpans
	closing                   bool
	closed                    chan struct{}
	debugFlags                DebugFlags
	debugAllEnqueuedSpans     map[oteltrace.SpanID]*tracev1.Span
	tracker                   *spanTracker
	observer                  *spanObserver
}

func NewSpanExportQueue(ctx context.Context, client otlptrace.Client) *SpanExportQueue {
	debug := systemContextFromContext(ctx).DebugFlags
	var observer *spanObserver
	if debug.Check(TrackSpanReferences) {
		observer = &spanObserver{referencedIDs: make(map[oteltrace.SpanID]oteltrace.SpanID)}
	}
	q := &SpanExportQueue{
		logger:                log.Ctx(ctx),
		client:                client,
		uploadC:               make(chan []*tracev1.ResourceSpans, 64),
		closed:                make(chan struct{}),
		debugFlags:            debug,
		debugAllEnqueuedSpans: make(map[oteltrace.SpanID]*tracev1.Span),
		tracker:               &spanTracker{observer: observer, debugFlags: debug},
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
	go q.runUploader()
	return q
}

func (q *SpanExportQueue) runUploader() {
	defer close(q.closed)
	for resourceSpans := range q.uploadC {
		ctx, ca := context.WithTimeout(context.Background(), 10*time.Second)
		if err := q.client.UploadTraces(ctx, resourceSpans); err != nil {
			q.logger.Err(err).Msg("error uploading traces")
		}
		ca()
	}
}

func (q *SpanExportQueue) onEvict(traceID unique.Handle[oteltrace.TraceID], buf *Buffer) {
	if buf.IsEmpty() {
		// if the buffer is not empty, it was evicted automatically
		return
	}

	select {
	case q.uploadC <- buf.Flush():
		q.logger.Warn().
			Str("traceID", traceID.Value().String()).
			Msg("trace export buffer is full, uploading oldest incomplete trace")
	default:
		q.logger.Warn().
			Str("traceID", traceID.Value().String()).
			Msg("trace export buffer and upload queues are full, dropping trace")
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

func (q *SpanExportQueue) resolveTraceIDMappingLocked(original, mapping unique.Handle[oteltrace.TraceID]) [][]*tracev1.ResourceSpans {
	q.knownTraceIDMappings.Add(original, mapping)

	if mapping == zeroTraceID && original != zeroTraceID {
		// mapping a trace id to zero indicates we should drop the trace
		q.pendingResourcesByTraceID.Remove(original)
		return nil
	}

	toUpload := [][]*tracev1.ResourceSpans{}
	if originalPending, ok := q.pendingResourcesByTraceID.Peek(original); ok {
		resourceSpans := originalPending.FlushAs(mapping)
		q.pendingResourcesByTraceID.Remove(original)
		toUpload = append(toUpload, resourceSpans)
	}

	if original != mapping {
		q.knownTraceIDMappings.Add(mapping, mapping)
		if targetPending, ok := q.pendingResourcesByTraceID.Peek(mapping); ok {
			resourceSpans := targetPending.FlushAs(mapping)
			q.pendingResourcesByTraceID.Remove(mapping)
			toUpload = append(toUpload, resourceSpans)
		}
	}
	return toUpload
}

func (q *SpanExportQueue) getTraceIDMappingLocked(id unique.Handle[oteltrace.TraceID]) (unique.Handle[oteltrace.TraceID], bool) {
	v, ok := q.knownTraceIDMappings.Get(id)
	return v, ok
}

var ErrShuttingDown = errors.New("exporter is shutting down")

func (q *SpanExportQueue) Enqueue(ctx context.Context, req *coltracepb.ExportTraceServiceRequest) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closing {
		return ErrShuttingDown
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
	var toUpload [][]*tracev1.ResourceSpans
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
				parentSpanID, ok := ToSpanID(span.ParentSpanId)
				if !ok {
					continue
				}
				traceID, ok := ToTraceID(span.TraceId)
				if !ok {
					continue
				}
				if _, ok := q.getTraceIDMappingLocked(traceID); !ok {
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
								log.Ctx(ctx).
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
									log.Ctx(ctx).
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
						q.observer.Observe(spanID)
						if isSampled && parentSpanID.IsValid() {
							q.observer.ObserveReference(parentSpanID, spanID)
						}
					}

					if !isSampled {
						// We have observed a new trace that is not sampled (regardless of
						// whether or not it is a root span). Resolve it using the zero
						// trace ID to indicate that all spans for this trace should be
						// dropped.
						_ = q.resolveTraceIDMappingLocked(traceID, zeroTraceID)
					} else if isRootSpan {
						// We have observed a new trace that is sampled and is a root span.
						// Resolve it using the mapped trace ID (if present), or its own
						// trace ID (indicating it does not need to be rewritten)
						toUpload = append(toUpload, q.resolveTraceIDMappingLocked(traceID, mappedTraceID)...)
					}
				}
			}
		}
	}

	// Pass 2
	var knownResources []*tracev1.ResourceSpans
	for _, resource := range req.ResourceSpans {
		resourceInfo := NewResourceInfo(resource.Resource, resource.SchemaUrl)
		knownResource := &tracev1.ResourceSpans{
			Resource:  resource.Resource,
			SchemaUrl: resource.SchemaUrl,
		}
		for _, scope := range resource.ScopeSpans {
			scopeInfo := NewScopeInfo(scope.Scope, scope.SchemaUrl)
			var knownSpans []*tracev1.Span
			for _, span := range scope.Spans {
				traceID, ok := ToTraceID(span.TraceId)
				if !ok {
					continue
				}
				if mapping, ok := q.getTraceIDMappingLocked(traceID); ok {
					if mapping == zeroTraceID {
						continue // the trace has been dropped
					}
					id := mapping.Value()
					copy(span.TraceId, id[:])
					knownSpans = append(knownSpans, span) // upload it
				} else {
					q.insertPendingSpanLocked(resourceInfo, scopeInfo, traceID, span)
				}
			}
			if len(knownSpans) > 0 {
				knownResource.ScopeSpans = append(knownResource.ScopeSpans, &tracev1.ScopeSpans{
					Scope:     scope.Scope,
					SchemaUrl: scope.SchemaUrl,
					Spans:     knownSpans,
				})
			}
		}
		if len(knownResource.ScopeSpans) > 0 {
			knownResources = append(knownResources, knownResource)
		}
	}
	if len(knownResources) > 0 {
		toUpload = append(toUpload, knownResources)
	}
	for _, res := range toUpload {
		q.uploadC <- res
	}
	return nil
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
		q.observer.wait(q.debugAllEnqueuedSpans)
	}()
	select {
	case <-done:
		return nil
	case <-time.After(maxDuration):
		return ErrMissingParentSpans
	}
}

func (q *SpanExportQueue) Close(ctx context.Context) error {
	q.mu.Lock()
	q.closing = true
	close(q.uploadC)
	q.mu.Unlock()
	select {
	case <-ctx.Done():
		log.Ctx(ctx).Error().Msg("exporter stopped before all traces could be exported")
		// drain uploadC
		for range q.uploadC {
		}
		return context.Cause(ctx)
	case <-q.closed:
		q.mu.Lock()
		defer q.mu.Unlock()
		err := q.runOnCloseChecksLocked()
		log.Ctx(ctx).Debug().Msg("exporter shut down")
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
	if incomplete {
		return ErrIncompleteTraces
	}
	return nil
}

type spanTracker struct {
	inflightSpans sync.Map
	allSpans      sync.Map
	debugFlags    DebugFlags
	observer      *spanObserver
	shutdownOnce  sync.Once
}

type spanInfo struct {
	Name        string
	SpanContext oteltrace.SpanContext
	Parent      oteltrace.SpanContext
}

// ForceFlush implements trace.SpanProcessor.
func (t *spanTracker) ForceFlush(context.Context) error {
	return nil
}

// OnEnd implements trace.SpanProcessor.
func (t *spanTracker) OnEnd(s sdktrace.ReadOnlySpan) {
	id := s.SpanContext().SpanID()
	t.inflightSpans.Delete(id)
}

// OnStart implements trace.SpanProcessor.
func (t *spanTracker) OnStart(_ context.Context, s sdktrace.ReadWriteSpan) {
	id := s.SpanContext().SpanID()
	t.inflightSpans.Store(id, struct{}{})
	if t.debugFlags.Check(TrackSpanReferences) {
		t.observer.Observe(id)
	}
	if t.debugFlags.Check(TrackAllSpans) {
		t.allSpans.Store(id, &spanInfo{
			Name:        s.Name(),
			SpanContext: s.SpanContext(),
			Parent:      s.Parent(),
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
				t.inflightSpans.Range(func(key, _ any) bool {
					if info, ok := t.allSpans.Load(key); ok {
						incompleteSpans = append(incompleteSpans, info.(*spanInfo))
					}
					return true
				})
				if len(incompleteSpans) > 0 {
					didWarn = true
					msg := startMsg("WARNING: spans not ended:\n")
					longestName := 0
					for _, span := range incompleteSpans {
						longestName = max(longestName, len(span.Name)+2)
					}
					for _, span := range incompleteSpans {
						fmt.Fprintf(msg, "%-*s (trace: %s | span: %s | parent: %s)\n", longestName, "'"+span.Name+"'",
							span.SpanContext.TraceID(), span.SpanContext.SpanID(), span.Parent.SpanID())
					}
					endMsg(msg)
				}
			} else {
				incompleteSpans := []string{}
				t.inflightSpans.Range(func(key, _ any) bool {
					incompleteSpans = append(incompleteSpans, key.(string))
					return true
				})
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
			msg := startMsg("All observed spans:\n")
			longestName := 0
			for _, span := range allSpans {
				longestName = max(longestName, len(span.Name)+2)
			}
			for _, span := range allSpans {
				fmt.Fprintf(msg, "%-*s (trace: %s | span: %s | parent: %s)\n", longestName, "'"+span.Name+"'",
					span.SpanContext.TraceID(), span.SpanContext.SpanID(), span.Parent.SpanID())
			}
			endMsg(msg)
		}
	})
	if didWarn {
		return ErrIncompleteSpans
	}
	return nil
}

type spanObserver struct {
	mu            sync.Mutex
	referencedIDs map[oteltrace.SpanID]oteltrace.SpanID
	unobservedIDs sync.WaitGroup
}

func (obs *spanObserver) ObserveReference(id oteltrace.SpanID, via oteltrace.SpanID) {
	obs.mu.Lock()
	defer obs.mu.Unlock()
	if _, referenced := obs.referencedIDs[id]; !referenced {
		obs.referencedIDs[id] = via // referenced, but not observed
		obs.unobservedIDs.Add(1)
	}
}

func (obs *spanObserver) Observe(id oteltrace.SpanID) {
	obs.mu.Lock()
	defer obs.mu.Unlock()
	if observed, referenced := obs.referencedIDs[id]; !referenced || observed.IsValid() { // NB: subtle condition
		obs.referencedIDs[id] = zeroSpanID
		if referenced {
			obs.unobservedIDs.Done()
		}
	}
}

func (obs *spanObserver) wait(debugAllEnqueuedSpans map[oteltrace.SpanID]*tracev1.Span) {
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-done:
			return
		case <-time.After(10 * time.Second):
			obs.mu.Lock()
			msg := startMsg("Waiting on unobserved spans:\n")
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
			obs.mu.Unlock()
		}
	}()
	obs.unobservedIDs.Wait()
}
