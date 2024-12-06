package trace

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"
	"unique"

	"github.com/pomerium/pomerium/internal/hashutil"
	"github.com/pomerium/pomerium/internal/log"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	oteltrace "go.opentelemetry.io/otel/trace"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonv1 "go.opentelemetry.io/proto/otlp/common/v1"
	resourcev1 "go.opentelemetry.io/proto/otlp/resource/v1"
	tracev1 "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"
)

type SpanExportQueue struct {
	mu                        sync.Mutex
	pendingResourcesByTraceID map[unique.Handle[oteltrace.TraceID]]*PendingResources
	knownTraceIDMappings      map[unique.Handle[oteltrace.TraceID]]unique.Handle[oteltrace.TraceID]
	uploadC                   chan []*tracev1.ResourceSpans
	closing                   bool
	closed                    chan struct{}
	debugFlags                DebugFlags
	debugAllObservedSpans     map[oteltrace.SpanID]*tracev1.Span
	tracker                   *spanTracker
	observer                  SpanObserver
}

func NewSpanExportQueue(ctx context.Context, client otlptrace.Client) *SpanExportQueue {
	debug := systemContextFromContext(ctx).DebugFlags
	var observer SpanObserver
	if debug.Check(TrackSpanReferences) {
		observer = &spanObserver{referencedIDs: make(map[oteltrace.SpanID]bool)}
	} else {
		observer = noopSpanObserver{}
	}
	q := &SpanExportQueue{
		pendingResourcesByTraceID: make(map[unique.Handle[oteltrace.TraceID]]*PendingResources),
		knownTraceIDMappings:      make(map[unique.Handle[oteltrace.TraceID]]unique.Handle[oteltrace.TraceID]),
		uploadC:                   make(chan []*tracev1.ResourceSpans, 8),
		closed:                    make(chan struct{}),
		debugFlags:                debug,
		debugAllObservedSpans:     make(map[oteltrace.SpanID]*tracev1.Span),
		tracker:                   &spanTracker{observer: observer, debugFlags: debug},
		observer:                  observer,
	}
	go func() {
		defer close(q.closed)
		for resourceSpans := range q.uploadC {
			if err := client.UploadTraces(context.Background(), resourceSpans); err != nil {
				log.Ctx(ctx).Err(err).Msg("error uploading traces")
			}
		}
	}()
	return q
}

func (q *SpanExportQueue) insertPendingSpanLocked(
	resource *ResourceInfo,
	scope *commonv1.InstrumentationScope,
	scopeSchema string,
	traceID unique.Handle[oteltrace.TraceID],
	span *tracev1.Span,
) {
	var pendingTraceResources *PendingResources
	if ptr, ok := q.pendingResourcesByTraceID[traceID]; ok {
		pendingTraceResources = ptr
	} else {
		pendingTraceResources = NewPendingResources()
		q.pendingResourcesByTraceID[traceID] = pendingTraceResources
	}
	pendingTraceResources.Insert(resource, scope, scopeSchema, span)
}

func (q *SpanExportQueue) resolveTraceIDMappingLocked(original, mapping unique.Handle[oteltrace.TraceID]) [][]*tracev1.ResourceSpans {
	q.knownTraceIDMappings[original] = mapping

	toUpload := [][]*tracev1.ResourceSpans{}
	if originalPending, ok := q.pendingResourcesByTraceID[original]; ok {
		resourceSpans := originalPending.AsResourceSpans(mapping)
		delete(q.pendingResourcesByTraceID, original)
		toUpload = append(toUpload, resourceSpans)
	}

	if original != mapping {
		q.knownTraceIDMappings[mapping] = mapping
		if targetPending, ok := q.pendingResourcesByTraceID[mapping]; ok {
			resourceSpans := targetPending.AsResourceSpans(mapping)
			delete(q.pendingResourcesByTraceID, mapping)
			toUpload = append(toUpload, resourceSpans)
		}
	}
	return toUpload
}

var ErrShuttingDown = errors.New("exporter is shutting down")

func (q *SpanExportQueue) Enqueue(ctx context.Context, req *coltracepb.ExportTraceServiceRequest) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closing {
		return ErrShuttingDown
	}

	var toUpload [][]*tracev1.ResourceSpans
	for _, resource := range req.ResourceSpans {
		for _, scope := range resource.ScopeSpans {
			for _, span := range scope.Spans {
				formatSpanName(span)
				spanID, ok := toSpanID(span.SpanId)
				if !ok {
					continue
				}
				if q.debugFlags.Check(TrackAllSpans) {
					q.debugAllObservedSpans[spanID] = span
				}
				parentSpanID, ok := toSpanID(span.ParentSpanId)
				if !ok {
					continue
				}
				if parentSpanID.IsValid() { // if parent is not a root span
					q.observer.ObserveReference(parentSpanID)
					continue
				}
				traceID, ok := toTraceID(span.TraceId)
				if !ok {
					continue
				}

				if _, ok := q.knownTraceIDMappings[traceID]; !ok {
					// observed a new root span with an unknown trace id
					var pomeriumTraceparent string
					for _, attr := range span.Attributes {
						if attr.Key == "pomerium.traceparent" {
							pomeriumTraceparent = attr.GetValue().GetStringValue()
							break
						}
					}
					var mappedTraceID unique.Handle[oteltrace.TraceID]

					if pomeriumTraceparent == "" {
						// no replacement id, map the trace to itself and release pending spans
						mappedTraceID = traceID
					} else {
						// this root span has an alternate traceparent. permanently rewrite
						// all spans of the old trace id to use the new trace id
						tp, err := ParseTraceparent(pomeriumTraceparent)
						if err != nil {
							log.Ctx(ctx).Err(err).Msg("error processing trace")
							continue
						}
						mappedTraceID = unique.Make(tp.TraceID())
					}

					toUpload = append(toUpload, q.resolveTraceIDMappingLocked(traceID, mappedTraceID)...)
				}
			}
		}
	}

	var knownResources []*tracev1.ResourceSpans
	for _, resource := range req.ResourceSpans {
		resourceInfo := newResourceInfo(resource.Resource, resource.SchemaUrl)
		knownResource := &tracev1.ResourceSpans{
			Resource:  resource.Resource,
			SchemaUrl: resource.SchemaUrl,
		}
		for _, scope := range resource.ScopeSpans {
			var knownSpans []*tracev1.Span
			for _, span := range scope.Spans {
				spanID, ok := toSpanID(span.SpanId)
				if !ok {
					continue
				}
				traceID, ok := toTraceID(span.TraceId)
				if !ok {
					continue
				}
				q.observer.Observe(spanID)
				if mapping, ok := q.knownTraceIDMappings[traceID]; ok {
					id := mapping.Value()
					copy(span.TraceId, id[:])
					knownSpans = append(knownSpans, span)
				} else {
					q.insertPendingSpanLocked(resourceInfo, scope.Scope, scope.SchemaUrl, traceID, span)
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
	ErrIncompleteUploads  = errors.New("exporter shut down with pending trace uploads")
	ErrMissingParentSpans = errors.New("exporter shut down with missing parent spans")
)

func (q *SpanExportQueue) WaitForSpans(maxDuration time.Duration) error {
	done := make(chan struct{})
	go func() {
		defer close(done)
		q.observer.Wait()
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
		return context.Cause(ctx)
	case <-q.closed:
		q.mu.Lock()
		defer q.mu.Unlock()
		if q.debugFlags.Check(TrackSpanReferences) {
			var unknownParentIDs []string
			for id, known := range q.observer.(*spanObserver).referencedIDs {
				if !known {
					unknownParentIDs = append(unknownParentIDs, id.String())
				}
			}
			if len(unknownParentIDs) > 0 {
				msg := startMsg("WARNING: parent spans referenced but never seen:\n")
				for _, str := range unknownParentIDs {
					msg.WriteString(str)
					msg.WriteString("\n")
				}
				endMsg(msg)
			}
		}
		didWarn := false
		incomplete := len(q.pendingResourcesByTraceID) > 0
		if incomplete && q.debugFlags.Check(WarnOnIncompleteTraces) {
			didWarn = true
			msg := startMsg("WARNING: exporter shut down with incomplete traces\n")
			for k, v := range q.pendingResourcesByTraceID {
				fmt.Fprintf(msg, "- Trace: %s\n", k.Value())
				for _, pendingScope := range v.scopesByResourceID {
					msg.WriteString("  - Resource:\n")
					for _, v := range pendingScope.resource.Resource.Attributes {
						fmt.Fprintf(msg, "     %s=%s\n", v.Key, v.Value.String())
					}
					for _, scope := range pendingScope.spansByScope {
						if scope.scope != nil {
							fmt.Fprintf(msg, "    Scope: %s\n", scope.scope.Name)
						} else {
							msg.WriteString("    Scope: (unknown)\n")
						}
						msg.WriteString("    Spans:\n")
						longestName := 0
						for _, span := range scope.spans {
							longestName = max(longestName, len(span.Name)+2)
						}
						for _, span := range scope.spans {
							spanID, ok := toSpanID(span.SpanId)
							if !ok {
								continue
							}
							traceID, ok := toTraceID(span.TraceId)
							if !ok {
								continue
							}
							parentSpanID, ok := toSpanID(span.ParentSpanId)
							if !ok {
								continue
							}
							_, seenParent := q.debugAllObservedSpans[parentSpanID]
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
			for k, v := range q.knownTraceIDMappings {
				if k != v {
					fmt.Fprintf(msg, "%s => %s\n", k.Value(), v.Value())
				} else {
					fmt.Fprintf(msg, "%s (no change)\n", k.Value())
				}
			}
			endMsg(msg)
		}
		if q.debugFlags.Check(LogAllSpans) || (didWarn && q.debugFlags.Check(LogAllSpansOnWarn)) {
			msg := startMsg("All exported spans:\n")
			longestName := 0
			for _, span := range q.debugAllObservedSpans {
				longestName = max(longestName, len(span.Name)+2)
			}
			for _, span := range q.debugAllObservedSpans {
				spanID, ok := toSpanID(span.SpanId)
				if !ok {
					continue
				}
				traceID, ok := toTraceID(span.TraceId)
				if !ok {
					continue
				}
				parentSpanID, ok := toSpanID(span.ParentSpanId)
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

		log.Ctx(ctx).Debug().Msg("exporter shut down")
		return nil
	}
}

type spanTracker struct {
	inflightSpans sync.Map
	allSpans      sync.Map
	debugFlags    DebugFlags
	observer      SpanObserver
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
	t.observer.Observe(id)
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
	t.shutdownOnce.Do(func() {
		didWarn := false
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
					msg.WriteString("Note: set TrackAllObservedSpans flag for more info\n")
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

	return nil
}

type PendingSpans struct {
	scope       *commonv1.InstrumentationScope
	scopeSchema string
	spans       []*tracev1.Span
}

func (ps *PendingSpans) Insert(span *tracev1.Span) {
	ps.spans = append(ps.spans, span)
}

func NewPendingSpans(scope *commonv1.InstrumentationScope, scopeSchema string) *PendingSpans {
	return &PendingSpans{
		scope:       scope,
		scopeSchema: scopeSchema,
	}
}

type PendingScopes struct {
	resource     *ResourceInfo
	spansByScope map[string]*PendingSpans
}

func (ps *PendingScopes) Insert(scope *commonv1.InstrumentationScope, scopeSchema string, span *tracev1.Span) {
	var spans *PendingSpans
	if sp, ok := ps.spansByScope[scope.GetName()]; ok {
		spans = sp
	} else {
		spans = NewPendingSpans(scope, scopeSchema)
		ps.spansByScope[scope.GetName()] = spans
	}
	spans.Insert(span)
}

func (ps *PendingScopes) AsScopeSpansList(rewriteTraceID unique.Handle[oteltrace.TraceID]) []*tracev1.ScopeSpans {
	out := make([]*tracev1.ScopeSpans, 0, len(ps.spansByScope))
	for _, spans := range ps.spansByScope {
		for _, span := range spans.spans {
			id := rewriteTraceID.Value()
			copy(span.TraceId, id[:])
		}
		scopeSpans := &tracev1.ScopeSpans{
			Scope:     spans.scope,
			SchemaUrl: spans.scopeSchema,
			Spans:     spans.spans,
		}
		out = append(out, scopeSpans)
	}
	return out
}

func NewPendingScopes(resource *ResourceInfo) *PendingScopes {
	return &PendingScopes{
		resource:     resource,
		spansByScope: make(map[string]*PendingSpans),
	}
}

type PendingResources struct {
	scopesByResourceID map[string]*PendingScopes
}

func (pr *PendingResources) Insert(resource *ResourceInfo, scope *commonv1.InstrumentationScope, scopeSchema string, span *tracev1.Span) {
	resourceEq := resource.ID()
	var scopes *PendingScopes
	if sc, ok := pr.scopesByResourceID[resourceEq]; ok {
		scopes = sc
	} else {
		scopes = NewPendingScopes(resource)
		pr.scopesByResourceID[resourceEq] = scopes
	}
	scopes.Insert(scope, scopeSchema, span)
}

func (pr *PendingResources) AsResourceSpans(rewriteTraceID unique.Handle[oteltrace.TraceID]) []*tracev1.ResourceSpans {
	out := make([]*tracev1.ResourceSpans, 0, len(pr.scopesByResourceID))
	for _, scopes := range pr.scopesByResourceID {
		resourceSpans := &tracev1.ResourceSpans{
			Resource:   scopes.resource.Resource,
			ScopeSpans: scopes.AsScopeSpansList(rewriteTraceID),
			SchemaUrl:  scopes.resource.Schema,
		}
		out = append(out, resourceSpans)
	}
	return out
}

func NewPendingResources() *PendingResources {
	return &PendingResources{scopesByResourceID: make(map[string]*PendingScopes)}
}

type ResourceInfo struct {
	Resource *resourcev1.Resource
	Schema   string
	ID       func() string
}

func newResourceInfo(resource *resourcev1.Resource, resourceSchema string) *ResourceInfo {
	r := &ResourceInfo{
		Resource: resource,
		Schema:   resourceSchema,
	}
	r.ID = sync.OnceValue(r.computeID)
	return r
}

func (r *ResourceInfo) computeID() string {
	hash := hashutil.NewDigest()
	tmp := resourcev1.Resource{
		Attributes: r.Resource.Attributes,
	}
	bytes, _ := proto.Marshal(&tmp)
	hash.WriteStringWithLen(r.Schema)
	hash.WriteWithLen(bytes)
	return base64.StdEncoding.EncodeToString(hash.Sum(nil))
}

type SpanObserver interface {
	ObserveReference(id oteltrace.SpanID)
	Observe(id oteltrace.SpanID)
	Wait()
}

type spanObserver struct {
	mu            sync.Mutex
	referencedIDs map[oteltrace.SpanID]bool
	unobservedIDs sync.WaitGroup
}

func (obs *spanObserver) ObserveReference(id oteltrace.SpanID) {
	obs.mu.Lock()
	defer obs.mu.Unlock()
	if _, referenced := obs.referencedIDs[id]; !referenced {
		obs.referencedIDs[id] = false // referenced, but not observed
		obs.unobservedIDs.Add(1)
	}
}

func (obs *spanObserver) Observe(id oteltrace.SpanID) {
	obs.mu.Lock()
	defer obs.mu.Unlock()
	if observed, referenced := obs.referencedIDs[id]; !observed { // NB: subtle condition
		obs.referencedIDs[id] = true
		if referenced {
			obs.unobservedIDs.Done()
		}
	}
}

func (obs *spanObserver) Wait() {
	obs.unobservedIDs.Wait()
}

type noopSpanObserver struct{}

func (noopSpanObserver) ObserveReference(oteltrace.SpanID) {}
func (noopSpanObserver) Observe(oteltrace.SpanID)          {}
func (noopSpanObserver) Wait()                             {}

func formatSpanName(span *tracev1.Span) {
	hasPath := strings.Contains(span.GetName(), "${path}")
	hasHost := strings.Contains(span.GetName(), "${host}")
	hasMethod := strings.Contains(span.GetName(), "${method}")
	if hasPath || hasHost || hasMethod {
		var u *url.URL
		var method string
		for _, attr := range span.Attributes {
			if attr.Key == "http.url" {
				u, _ = url.Parse(attr.Value.GetStringValue())
			}
			if attr.Key == "http.method" {
				method = attr.Value.GetStringValue()
			}
		}
		if u != nil {
			if hasPath {
				span.Name = strings.ReplaceAll(span.Name, "${path}", u.Path)
			}
			if hasHost {
				span.Name = strings.ReplaceAll(span.Name, "${host}", u.Host)
			}
			if hasMethod {
				span.Name = strings.ReplaceAll(span.Name, "${method}", method)
			}
		}
	}
}

var (
	zeroSpanID  oteltrace.SpanID
	zeroTraceID = unique.Make(oteltrace.TraceID([16]byte{}))
)

func toSpanID(bytes []byte) (oteltrace.SpanID, bool) {
	switch len(bytes) {
	case 0:
		return zeroSpanID, true
	case 8:
		return oteltrace.SpanID(bytes), true
	}
	return zeroSpanID, false
}

func toTraceID(bytes []byte) (unique.Handle[oteltrace.TraceID], bool) {
	switch len(bytes) {
	case 0:
		return zeroTraceID, true
	case 16:
		return unique.Make(oteltrace.TraceID(bytes)), true
	}
	return zeroTraceID, false
}
