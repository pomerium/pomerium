package trace

import (
	"context"
	"encoding/base64"
	"net"
	"net/url"
	"strings"
	"sync"

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

func (ptr *PendingScopes) Delete(scope *commonv1.InstrumentationScope) (cascade bool) {
	delete(ptr.spansByScope, scope.GetName())
	return len(ptr.spansByScope) == 0
}

func (ptr *PendingScopes) AsScopeSpansList(rewriteTraceId oteltrace.TraceID) []*tracev1.ScopeSpans {
	out := make([]*tracev1.ScopeSpans, 0, len(ptr.spansByScope))
	for _, spans := range ptr.spansByScope {
		for _, span := range spans.spans {
			span.TraceId = rewriteTraceId[:]
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

func (ptr *PendingResources) Delete(resource *ResourceInfo, scope *commonv1.InstrumentationScope) (cascade bool) {
	resourceEq := resource.ID()
	if ptr.scopesByResourceID[resourceEq].Delete(scope) {
		delete(ptr.scopesByResourceID, resourceEq)
	}
	return len(ptr.scopesByResourceID) == 0
}

func (ptr *PendingResources) AsResourceSpans(rewriteTraceId oteltrace.TraceID) []*tracev1.ResourceSpans {
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

type SpanExportQueue struct {
	mu                        sync.Mutex
	pendingResourcesByTraceId map[string]*PendingResources
	knownTraceIdMappings      map[string]oteltrace.TraceID
	uploadC                   chan []*tracev1.ResourceSpans
}

func NewSpanExportQueue(ctx context.Context, client otlptrace.Client) *SpanExportQueue {
	q := &SpanExportQueue{
		pendingResourcesByTraceId: make(map[string]*PendingResources),
		knownTraceIdMappings:      make(map[string]oteltrace.TraceID),
		uploadC:                   make(chan []*tracev1.ResourceSpans, 8),
	}
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case resourceSpans := <-q.uploadC:
				if err := client.UploadTraces(ctx, resourceSpans); err != nil {
					log.Ctx(ctx).Err(err).Msg("error uploading traces")
				}
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
	spanTraceIdHex := oteltrace.TraceID(span.TraceId).String()
	var pendingTraceResources *PendingResources
	if ptr, ok := q.pendingResourcesByTraceId[spanTraceIdHex]; ok {
		pendingTraceResources = ptr
	} else {
		pendingTraceResources = NewPendingResources()
		q.pendingResourcesByTraceId[spanTraceIdHex] = pendingTraceResources
	}
	pendingTraceResources.Insert(resource, scope, scopeSchema, span)
}

func (q *SpanExportQueue) resolveTraceIdMappingLocked(resource *ResourceInfo, scope *commonv1.InstrumentationScope, scopeSchema string, span *tracev1.Span, mapping oteltrace.TraceID) {
	originalTraceIdHex := oteltrace.TraceID(span.TraceId).String()
	q.insertPendingSpanLocked(resource, scope, scopeSchema, span)
	q.knownTraceIdMappings[originalTraceIdHex] = mapping
	toUpload := q.pendingResourcesByTraceId[originalTraceIdHex].AsResourceSpans(mapping)
	if q.pendingResourcesByTraceId[originalTraceIdHex].Delete(resource, scope) {
		delete(q.pendingResourcesByTraceId, originalTraceIdHex)
	}
	q.uploadC <- toUpload
}

func (q *SpanExportQueue) Enqueue(ctx context.Context, req *coltracepb.ExportTraceServiceRequest) {
	q.mu.Lock()
	defer q.mu.Unlock()

	var immediateUpload []*tracev1.ResourceSpans
	for _, resource := range req.ResourceSpans {
		resourceInfo := newResourceInfo(resource.Resource, resource.SchemaUrl)
		knownResources := &tracev1.ResourceSpans{
			Resource:  resource.Resource,
			SchemaUrl: resource.SchemaUrl,
		}
		for _, scope := range resource.ScopeSpans {
			var knownSpans []*tracev1.Span
			for _, span := range scope.Spans {
				spanTraceId := oteltrace.TraceID(span.TraceId)
				spanTraceIdHex := oteltrace.TraceID(span.TraceId).String()

				formatSpanName(span)
				if len(span.ParentSpanId) == 0 {
					// observed a new root span
					var pomeriumTraceparent string
					for _, attr := range span.Attributes {
						if attr.Key == "pomerium.traceparent" {
							pomeriumTraceparent = attr.GetValue().GetStringValue()
							break
						}
					}
					var targetTraceID oteltrace.TraceID

					if pomeriumTraceparent == "" {
						// no replacement id, map the trace to itself and release pending spans
						targetTraceID = spanTraceId
					} else {
						// this root span has an alternate traceparent. permanently rewrite
						// all spans of the old trace id to use the new trace id
						tp, err := ParseTraceparent(pomeriumTraceparent)
						if err != nil {
							log.Ctx(ctx).Err(err).Msg("error processing trace")
							continue
						}
						targetTraceID = tp.TraceID()
					}

					q.resolveTraceIdMappingLocked(resourceInfo, scope.Scope, scope.SchemaUrl, span, targetTraceID)
				} else {
					if rewrite, ok := q.knownTraceIdMappings[spanTraceIdHex]; ok {
						span.TraceId = rewrite[:]
						knownSpans = append(knownSpans, span)
					} else {
						q.insertPendingSpanLocked(resourceInfo, scope.Scope, scope.SchemaUrl, span)
					}
				}
			}
			if len(knownSpans) > 0 {
				knownResources.ScopeSpans = append(knownResources.ScopeSpans, &tracev1.ScopeSpans{
					Scope:     scope.Scope,
					SchemaUrl: scope.SchemaUrl,
					Spans:     knownSpans,
				})
			}
		}
		if len(knownResources.ScopeSpans) > 0 {
			immediateUpload = append(immediateUpload, knownResources)
		}
	}
	if len(immediateUpload) > 0 {
		q.uploadC <- immediateUpload
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
func (srv *Server) Export(ctx context.Context, req *coltracepb.ExportTraceServiceRequest) (*coltracepb.ExportTraceServiceResponse, error) {
	srv.spanExportQueue.Enqueue(ctx, req)
	return &coltracepb.ExportTraceServiceResponse{}, nil
}

type Server struct {
	coltracepb.UnimplementedTraceServiceServer
	spanExportQueue *SpanExportQueue
}

func NewServer(ctx context.Context, client otlptrace.Client) *Server {
	client.Start(ctx)
	return &Server{
		spanExportQueue: NewSpanExportQueue(ctx, client),
	}
}

func (srv *Server) Start(ctx context.Context) otlptrace.Client {
	lis := bufconn.Listen(4096)
	gs := grpc.NewServer(grpc.Creds(insecure.NewCredentials()))
	coltracepb.RegisterTraceServiceServer(gs, srv)
	go gs.Serve(lis)
	cc, err := grpc.NewClient("passthrough://ignore",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return lis.Dial()
		}), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		panic(err)
	}
	return otlptracegrpc.NewClient(otlptracegrpc.WithGRPCConn(cc))
}
