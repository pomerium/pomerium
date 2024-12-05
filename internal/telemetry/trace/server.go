package trace

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
	"unique"

	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonv1 "go.opentelemetry.io/proto/otlp/common/v1"
	resourcev1 "go.opentelemetry.io/proto/otlp/resource/v1"
	tracev1 "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"

	"github.com/pomerium/pomerium/internal/hashutil"
	"github.com/pomerium/pomerium/internal/log"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	oteltrace "go.opentelemetry.io/otel/trace"
)

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

func (ptr *PendingScopes) Insert(scope *commonv1.InstrumentationScope, scopeSchema string, span *tracev1.Span) {
	var spans *PendingSpans
	if sp, ok := ptr.spansByScope[scope.GetName()]; ok {
		spans = sp
	} else {
		spans = NewPendingSpans(scope, scopeSchema)
		ptr.spansByScope[scope.GetName()] = spans
	}
	spans.Insert(span)
}

func (ptr *PendingScopes) AsScopeSpansList(rewriteTraceId unique.Handle[oteltrace.TraceID]) []*tracev1.ScopeSpans {
	out := make([]*tracev1.ScopeSpans, 0, len(ptr.spansByScope))
	for _, spans := range ptr.spansByScope {
		for _, span := range spans.spans {
			id := rewriteTraceId.Value()
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

func (ptr *PendingResources) Insert(resource *ResourceInfo, scope *commonv1.InstrumentationScope, scopeSchema string, span *tracev1.Span) {
	resourceEq := resource.ID()
	var scopes *PendingScopes
	if sc, ok := ptr.scopesByResourceID[resourceEq]; ok {
		scopes = sc
	} else {
		scopes = NewPendingScopes(resource)
		ptr.scopesByResourceID[resourceEq] = scopes
	}
	scopes.Insert(scope, scopeSchema, span)
}

func (ptr *PendingResources) AsResourceSpans(rewriteTraceId unique.Handle[oteltrace.TraceID]) []*tracev1.ResourceSpans {
	out := make([]*tracev1.ResourceSpans, 0, len(ptr.scopesByResourceID))
	for _, scopes := range ptr.scopesByResourceID {
		resourceSpans := &tracev1.ResourceSpans{
			Resource:   scopes.resource.Resource,
			ScopeSpans: scopes.AsScopeSpansList(rewriteTraceId),
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

type spanObserver struct {
	mu            sync.Mutex
	referencedIDs map[unique.Handle[oteltrace.SpanID]]bool
	unobservedIDs sync.WaitGroup
}

func (obs *spanObserver) ObserveReference(id unique.Handle[oteltrace.SpanID]) {
	obs.mu.Lock()
	defer obs.mu.Unlock()
	if _, referenced := obs.referencedIDs[id]; !referenced {
		obs.referencedIDs[id] = false // referenced, but not observed
		obs.unobservedIDs.Add(1)
	}
}

func (obs *spanObserver) Observe(id unique.Handle[oteltrace.SpanID]) {
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

type SpanExportQueue struct {
	mu                        sync.Mutex
	pendingResourcesByTraceId map[unique.Handle[oteltrace.TraceID]]*PendingResources
	knownTraceIdMappings      map[unique.Handle[oteltrace.TraceID]]unique.Handle[oteltrace.TraceID]
	uploadC                   chan []*tracev1.ResourceSpans
	closing                   bool
	closed                    chan struct{}
	debugLevel                int
	debugAllObservedSpans     map[unique.Handle[oteltrace.SpanID]]*tracev1.Span
	tracker                   *spanTracker
	observer                  *spanObserver
}

func NewSpanExportQueue(ctx context.Context, client otlptrace.Client) *SpanExportQueue {
	observer := &spanObserver{referencedIDs: make(map[unique.Handle[oteltrace.SpanID]]bool)}
	debugLevel := systemContextFromContext(ctx).DebugLevel
	q := &SpanExportQueue{
		pendingResourcesByTraceId: make(map[unique.Handle[oteltrace.TraceID]]*PendingResources),
		knownTraceIdMappings:      make(map[unique.Handle[oteltrace.TraceID]]unique.Handle[oteltrace.TraceID]),
		uploadC:                   make(chan []*tracev1.ResourceSpans, 8),
		closed:                    make(chan struct{}),
		debugLevel:                debugLevel,
		debugAllObservedSpans:     make(map[unique.Handle[oteltrace.SpanID]]*tracev1.Span),
		tracker:                   &spanTracker{observer: observer, debugLevel: debugLevel},
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

type WithSchema[T any] struct {
	Value  T
	Schema string
}

func (q *SpanExportQueue) insertPendingSpanLocked(resource *ResourceInfo, scope *commonv1.InstrumentationScope, scopeSchema string, span *tracev1.Span) {
	spanTraceId := unique.Make(oteltrace.TraceID(span.TraceId))
	var pendingTraceResources *PendingResources
	if ptr, ok := q.pendingResourcesByTraceId[spanTraceId]; ok {
		pendingTraceResources = ptr
	} else {
		pendingTraceResources = NewPendingResources()
		q.pendingResourcesByTraceId[spanTraceId] = pendingTraceResources
	}
	pendingTraceResources.Insert(resource, scope, scopeSchema, span)
}

func (q *SpanExportQueue) resolveTraceIdMappingLocked(original, mapping unique.Handle[oteltrace.TraceID]) [][]*tracev1.ResourceSpans {
	q.knownTraceIdMappings[original] = mapping

	toUpload := [][]*tracev1.ResourceSpans{}
	if originalPending, ok := q.pendingResourcesByTraceId[original]; ok {
		resourceSpans := originalPending.AsResourceSpans(mapping)
		delete(q.pendingResourcesByTraceId, original)
		toUpload = append(toUpload, resourceSpans)
	}

	if original != mapping {
		q.knownTraceIdMappings[mapping] = mapping
		if targetPending, ok := q.pendingResourcesByTraceId[mapping]; ok {
			resourceSpans := targetPending.AsResourceSpans(mapping)
			delete(q.pendingResourcesByTraceId, mapping)
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
				spanId := unique.Make(oteltrace.SpanID(span.SpanId))
				parentSpanId := parentSpanID(span.ParentSpanId)
				if q.debugLevel >= 1 {
					q.debugAllObservedSpans[spanId] = span
				}
				if parentSpanId != rootSpanId {
					q.observer.ObserveReference(parentSpanId)
					continue
				}
				spanTraceId := unique.Make(oteltrace.TraceID(span.TraceId))

				if _, ok := q.knownTraceIdMappings[spanTraceId]; !ok {
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
						mappedTraceID = spanTraceId
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

					toUpload = append(toUpload, q.resolveTraceIdMappingLocked(spanTraceId, mappedTraceID)...)
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
				spanID := unique.Make(oteltrace.SpanID(span.SpanId))
				spanTraceId := unique.Make(oteltrace.TraceID(span.TraceId))
				q.observer.Observe(spanID)
				if mapping, ok := q.knownTraceIdMappings[spanTraceId]; ok {
					id := mapping.Value()
					copy(span.TraceId, id[:])
					knownSpans = append(knownSpans, span)
				} else {
					q.insertPendingSpanLocked(resourceInfo, scope.Scope, scope.SchemaUrl, span)
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

var rootSpanId = unique.Make(oteltrace.SpanID([8]byte{}))

func parentSpanID(value []byte) unique.Handle[oteltrace.SpanID] {
	if len(value) == 0 {
		return rootSpanId
	}
	return unique.Make(oteltrace.SpanID(value))
}

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
		if q.debugLevel >= 1 {
			var unknownParentIds []string
			for id, known := range q.observer.referencedIDs {
				if !known {
					unknownParentIds = append(unknownParentIds, id.Value().String())
				}
			}
			if len(unknownParentIds) > 0 {
				msg := strings.Builder{}
				msg.WriteString("==================================================\n")
				msg.WriteString("WARNING: parent spans referenced but never seen:\n")
				for _, str := range unknownParentIds {
					msg.WriteString(str)
					msg.WriteString("\n")
				}
				msg.WriteString("==================================================\n")
				fmt.Fprint(os.Stderr, msg.String())
			}
		}
		incomplete := len(q.pendingResourcesByTraceId) > 0
		if incomplete || q.debugLevel >= 3 {
			msg := strings.Builder{}
			if incomplete && q.debugLevel >= 1 {
				msg.WriteString("==================================================\n")
				msg.WriteString("WARNING: exporter shut down with incomplete traces\n")
				for k, v := range q.pendingResourcesByTraceId {
					msg.WriteString(fmt.Sprintf("- Trace: %s\n", k.Value()))
					for _, pendingScope := range v.scopesByResourceID {
						msg.WriteString("  - Resource:\n")
						for _, v := range pendingScope.resource.Resource.Attributes {
							msg.WriteString(fmt.Sprintf("     %s=%s\n", v.Key, v.Value.String()))
						}
						for _, scope := range pendingScope.spansByScope {
							if scope.scope != nil {
								msg.WriteString(fmt.Sprintf("    Scope: %s\n", scope.scope.Name))
							} else {
								msg.WriteString("    Scope: (unknown)\n")
							}
							msg.WriteString("    Spans:\n")
							longestName := 0
							for _, span := range scope.spans {
								longestName = max(longestName, len(span.Name)+2)
							}
							for _, span := range scope.spans {
								parentSpanId := parentSpanID(span.ParentSpanId)
								_, seenParent := q.debugAllObservedSpans[parentSpanId]
								var missing string
								if !seenParent {
									missing = " [missing]"
								}
								msg.WriteString(fmt.Sprintf("    - %-*s (trace: %s | span: %s | parent:%s %s)\n", longestName,
									"'"+span.Name+"'", hex.EncodeToString(span.TraceId), hex.EncodeToString(span.SpanId), missing, parentSpanId.Value()))
								for _, attr := range span.Attributes {
									if attr.Key == "caller" {
										msg.WriteString(fmt.Sprintf("      => caller: '%s'\n", attr.Value.GetStringValue()))
									}
								}
							}
						}
					}
				}
				msg.WriteString("==================================================\n")
			}
			if (incomplete && q.debugLevel >= 2) || (!incomplete && q.debugLevel >= 3) {
				msg.WriteString("==================================================\n")
				msg.WriteString("Known trace ids:\n")
				for k, v := range q.knownTraceIdMappings {
					if k != v {
						msg.WriteString(fmt.Sprintf("%s => %s\n", k.Value(), v.Value()))
					} else {
						msg.WriteString(fmt.Sprintf("%s (no change)\n", k.Value()))
					}
				}
				msg.WriteString("==================================================\n")
				msg.WriteString("All exported spans:\n")
				longestName := 0
				for _, span := range q.debugAllObservedSpans {
					longestName = max(longestName, len(span.Name)+2)
				}
				for _, span := range q.debugAllObservedSpans {
					traceid := span.TraceId
					spanid := span.SpanId
					msg.WriteString(fmt.Sprintf("%-*s (trace: %s | span: %s | parent: %s)", longestName,
						"'"+span.Name+"'", hex.EncodeToString(traceid[:]), hex.EncodeToString(spanid[:]), parentSpanID(span.ParentSpanId).Value()))
					var foundCaller bool
					for _, attr := range span.Attributes {
						if attr.Key == "caller" {
							msg.WriteString(fmt.Sprintf(" => %s\n", attr.Value.GetStringValue()))
							foundCaller = true
							break
						}
					}
					if !foundCaller {
						msg.WriteString("\n")
					}
				}
				msg.WriteString("==================================================\n")
			}
			if msg.Len() > 0 {
				fmt.Fprint(os.Stderr, msg.String())
			}
			if incomplete {
				return ErrIncompleteTraces
			}
		}
		log.Ctx(ctx).Debug().Msg("exporter shut down")
		return nil
	}
}

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

// Export implements ptraceotlp.GRPCServer.
func (srv *ExporterServer) Export(ctx context.Context, req *coltracepb.ExportTraceServiceRequest) (*coltracepb.ExportTraceServiceResponse, error) {
	srv.spanExportQueue.Enqueue(ctx, req)
	return &coltracepb.ExportTraceServiceResponse{}, nil
}

type ExporterServer struct {
	coltracepb.UnimplementedTraceServiceServer
	spanExportQueue *SpanExportQueue
	server          *grpc.Server
	remoteClient    otlptrace.Client
	cc              *grpc.ClientConn
}

func NewServer(ctx context.Context, remoteClient otlptrace.Client) *ExporterServer {
	if err := remoteClient.Start(ctx); err != nil {
		panic(err)
	}
	ex := &ExporterServer{
		spanExportQueue: NewSpanExportQueue(ctx, remoteClient),
		remoteClient:    remoteClient,
		server:          grpc.NewServer(grpc.Creds(insecure.NewCredentials())),
	}
	coltracepb.RegisterTraceServiceServer(ex.server, ex)
	return ex
}

func (srv *ExporterServer) Start(ctx context.Context) {
	lis := bufconn.Listen(4096)
	go srv.server.Serve(lis)
	cc, err := grpc.NewClient("passthrough://ignore",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return lis.Dial()
		}), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		panic(err)
	}
	srv.cc = cc
}

func (srv *ExporterServer) NewClient() otlptrace.Client {
	return otlptracegrpc.NewClient(otlptracegrpc.WithGRPCConn(srv.cc))
}

func (srv *ExporterServer) SpanProcessors() []sdktrace.SpanProcessor {
	return []sdktrace.SpanProcessor{srv.spanExportQueue.tracker}
}

func (srv *ExporterServer) Shutdown(ctx context.Context) error {
	stopped := make(chan struct{})
	go func() {
		srv.server.GracefulStop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-ctx.Done():
		return context.Cause(ctx)
	}
	var errs []error
	if err := srv.spanExportQueue.WaitForSpans(5 * time.Second); err != nil {
		errs = append(errs, err)
	}
	if err := srv.spanExportQueue.Close(ctx); err != nil {
		errs = append(errs, err)
	}
	if err := srv.remoteClient.Stop(ctx); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

type spanTracker struct {
	inflightSpans sync.Map
	allSpans      sync.Map
	debugLevel    int
	observer      *spanObserver
	shutdownOnce  sync.Once
}

type spanInfo struct {
	Name        string
	SpanContext trace.SpanContext
	Parent      trace.SpanContext
}

// ForceFlush implements trace.SpanProcessor.
func (t *spanTracker) ForceFlush(ctx context.Context) error {
	return nil
}

// OnEnd implements trace.SpanProcessor.
func (t *spanTracker) OnEnd(s sdktrace.ReadOnlySpan) {
	id := unique.Make(s.SpanContext().SpanID())
	t.inflightSpans.Delete(id)
}

// OnStart implements trace.SpanProcessor.
func (t *spanTracker) OnStart(parent context.Context, s sdktrace.ReadWriteSpan) {
	id := unique.Make(s.SpanContext().SpanID())
	t.inflightSpans.Store(id, struct{}{})
	t.observer.Observe(id)
	if t.debugLevel >= 3 {
		t.allSpans.Store(id, &spanInfo{
			Name:        s.Name(),
			SpanContext: s.SpanContext(),
			Parent:      s.Parent(),
		})
	}
}

// Shutdown implements trace.SpanProcessor.
func (t *spanTracker) Shutdown(ctx context.Context) error {
	t.shutdownOnce.Do(func() {
		msg := strings.Builder{}
		if t.debugLevel >= 1 {
			incompleteSpans := []*spanInfo{}
			t.inflightSpans.Range(func(key, value any) bool {
				if info, ok := t.allSpans.Load(key); ok {
					incompleteSpans = append(incompleteSpans, info.(*spanInfo))
				}
				return true
			})
			if len(incompleteSpans) > 0 {
				msg.WriteString("==================================================\n")
				msg.WriteString("WARNING: spans not ended:\n")
				longestName := 0
				for _, span := range incompleteSpans {
					longestName = max(longestName, len(span.Name)+2)
				}
				for _, span := range incompleteSpans {
					msg.WriteString(fmt.Sprintf("%-*s (trace: %s | span: %s | parent: %s)\n", longestName, "'"+span.Name+"'",
						span.SpanContext.TraceID(), span.SpanContext.SpanID(), span.Parent.SpanID()))
				}
				msg.WriteString("==================================================\n")
			}
		}
		if t.debugLevel >= 3 {
			allSpans := []*spanInfo{}
			t.allSpans.Range(func(key, value any) bool {
				allSpans = append(allSpans, value.(*spanInfo))
				return true
			})
			msg.WriteString("==================================================\n")
			msg.WriteString("All observed spans:\n")
			longestName := 0
			for _, span := range allSpans {
				longestName = max(longestName, len(span.Name)+2)
			}
			for _, span := range allSpans {
				msg.WriteString(fmt.Sprintf("%-*s (trace: %s | span: %s | parent: %s)\n", longestName, "'"+span.Name+"'",
					span.SpanContext.TraceID(), span.SpanContext.SpanID(), span.Parent.SpanID()))
			}
			msg.WriteString("==================================================\n")
		}
		if msg.Len() > 0 {
			fmt.Fprint(os.Stderr, msg.String())
		}
	})

	return nil
}
