package trace

import (
	"encoding/base64"
	"sync"
	"unique"

	"github.com/pomerium/pomerium/internal/hashutil"
	oteltrace "go.opentelemetry.io/otel/trace"
	commonv1 "go.opentelemetry.io/proto/otlp/common/v1"
	resourcev1 "go.opentelemetry.io/proto/otlp/resource/v1"
	tracev1 "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"
)

type ScopeBuffer struct {
	scope *ScopeInfo
	spans []*tracev1.Span
}

func (ps *ScopeBuffer) Insert(span *tracev1.Span) {
	ps.spans = append(ps.spans, span)
}

func NewScopeBuffer(scope *ScopeInfo) *ScopeBuffer {
	return &ScopeBuffer{
		scope: scope,
	}
}

type ResourceBuffer struct {
	resource     *ResourceInfo
	spansByScope map[string]*ScopeBuffer
}

func NewResourceBuffer(resource *ResourceInfo) *ResourceBuffer {
	return &ResourceBuffer{
		resource:     resource,
		spansByScope: make(map[string]*ScopeBuffer),
	}
}

func (ps *ResourceBuffer) Insert(scope *ScopeInfo, span *tracev1.Span) {
	var spans *ScopeBuffer
	if sp, ok := ps.spansByScope[scope.ID()]; ok {
		spans = sp
	} else {
		spans = NewScopeBuffer(scope)
		ps.spansByScope[scope.ID()] = spans
	}
	spans.Insert(span)
}

func (ps *ResourceBuffer) Flush() []*tracev1.ScopeSpans {
	out := make([]*tracev1.ScopeSpans, 0, len(ps.spansByScope))
	for _, spans := range ps.spansByScope {
		scopeSpans := &tracev1.ScopeSpans{
			Scope:     spans.scope.Scope,
			SchemaUrl: spans.scope.Schema,
			Spans:     spans.spans,
		}
		out = append(out, scopeSpans)
	}
	clear(ps.spansByScope)
	return out
}

func (ps *ResourceBuffer) FlushAs(rewriteTraceID unique.Handle[oteltrace.TraceID]) []*tracev1.ScopeSpans {
	out := make([]*tracev1.ScopeSpans, 0, len(ps.spansByScope))
	for _, spans := range ps.spansByScope {
		for _, span := range spans.spans {
			id := rewriteTraceID.Value()
			copy(span.TraceId, id[:])
		}
		scopeSpans := &tracev1.ScopeSpans{
			Scope:     spans.scope.Scope,
			SchemaUrl: spans.scope.Schema,
			Spans:     spans.spans,
		}
		out = append(out, scopeSpans)
	}
	clear(ps.spansByScope)
	return out
}

type TraceBuffer struct {
	traceID            unique.Handle[oteltrace.TraceID]
	scopesByResourceID map[string]*ResourceBuffer
}

func NewTraceBuffer() *TraceBuffer {
	return &TraceBuffer{
		scopesByResourceID: make(map[string]*ResourceBuffer),
	}
}

func (pr *TraceBuffer) Insert(resource *ResourceInfo, scope *ScopeInfo, span *tracev1.Span) {
	resourceEq := resource.ID()
	var scopes *ResourceBuffer
	if sc, ok := pr.scopesByResourceID[resourceEq]; ok {
		scopes = sc
	} else {
		scopes = NewResourceBuffer(resource)
		pr.scopesByResourceID[resourceEq] = scopes
	}
	scopes.Insert(scope, span)
}

func (pr *TraceBuffer) Flush() []*tracev1.ResourceSpans {
	out := make([]*tracev1.ResourceSpans, 0, len(pr.scopesByResourceID))
	for _, scopes := range pr.scopesByResourceID {
		resourceSpans := &tracev1.ResourceSpans{
			Resource:   scopes.resource.Resource,
			ScopeSpans: scopes.Flush(),
			SchemaUrl:  scopes.resource.Schema,
		}
		out = append(out, resourceSpans)
	}
	clear(pr.scopesByResourceID)
	return out
}

func (pr *TraceBuffer) FlushAs(rewriteTraceID unique.Handle[oteltrace.TraceID]) []*tracev1.ResourceSpans {
	out := make([]*tracev1.ResourceSpans, 0, len(pr.scopesByResourceID))
	for _, scopes := range pr.scopesByResourceID {
		resourceSpans := &tracev1.ResourceSpans{
			Resource:   scopes.resource.Resource,
			ScopeSpans: scopes.FlushAs(rewriteTraceID),
			SchemaUrl:  scopes.resource.Schema,
		}
		out = append(out, resourceSpans)
	}
	clear(pr.scopesByResourceID)
	return out
}

func (pr *TraceBuffer) IsEmpty() bool {
	return len(pr.scopesByResourceID) == 0
}

type ResourceInfo struct {
	Resource *resourcev1.Resource
	Schema   string
	ID       func() string
}

func NewResourceInfo(resource *resourcev1.Resource, resourceSchema string) *ResourceInfo {
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

type ScopeInfo struct {
	Scope  *commonv1.InstrumentationScope
	Schema string
	ID     func() string
}

func NewScopeInfo(scope *commonv1.InstrumentationScope, scopeSchema string) *ScopeInfo {
	s := &ScopeInfo{
		Scope:  scope,
		Schema: scopeSchema,
	}
	s.ID = sync.OnceValue(s.computeID)
	return s
}

func (r *ScopeInfo) computeID() string {
	if r.Scope == nil {
		return "(unknown)"
	}
	hash := hashutil.NewDigest()
	tmp := commonv1.InstrumentationScope{
		Name:       r.Scope.Name,
		Version:    r.Scope.Version,
		Attributes: r.Scope.Attributes,
	}
	bytes, _ := proto.Marshal(&tmp)
	hash.WriteStringWithLen(r.Schema)
	hash.WriteWithLen(bytes)
	return base64.StdEncoding.EncodeToString(hash.Sum(nil))
}
