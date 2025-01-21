package tracetest

import (
	"cmp"
	"encoding/base64"
	"maps"
	"slices"
	"sync"

	"github.com/pomerium/pomerium/internal/hashutil"
	commonv1 "go.opentelemetry.io/proto/otlp/common/v1"
	resourcev1 "go.opentelemetry.io/proto/otlp/resource/v1"
	tracev1 "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"
)

type ScopeBuffer struct {
	scope *ScopeInfo
	spans []*tracev1.Span
}

func (sb *ScopeBuffer) Insert(spans ...*tracev1.Span) {
	sb.spans = append(sb.spans, spans...)
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

func (rb *ResourceBuffer) Insert(scope *ScopeInfo, span *tracev1.Span) {
	var spans *ScopeBuffer
	if sp, ok := rb.spansByScope[scope.ID()]; ok {
		spans = sp
	} else {
		spans = NewScopeBuffer(scope)
		rb.spansByScope[scope.ID()] = spans
	}
	spans.Insert(span)
}

func (rb *ResourceBuffer) Flush() []*tracev1.ScopeSpans {
	out := make([]*tracev1.ScopeSpans, 0, len(rb.spansByScope))
	for _, key := range slices.Sorted(maps.Keys(rb.spansByScope)) {
		spans := rb.spansByScope[key]
		slices.SortStableFunc(spans.spans, func(a, b *tracev1.Span) int {
			return cmp.Compare(a.StartTimeUnixNano, b.StartTimeUnixNano)
		})
		scopeSpans := &tracev1.ScopeSpans{
			Scope:     spans.scope.Scope,
			SchemaUrl: spans.scope.Schema,
			Spans:     spans.spans,
		}
		out = append(out, scopeSpans)
	}
	clear(rb.spansByScope)
	return out
}

func (rb *ResourceBuffer) Merge(other *ResourceBuffer) {
	for scope, otherSpans := range other.spansByScope {
		if ourSpans, ok := rb.spansByScope[scope]; !ok {
			rb.spansByScope[scope] = otherSpans
		} else {
			ourSpans.Insert(otherSpans.spans...)
		}
	}
	clear(other.spansByScope)
}

type Buffer struct {
	scopesByResourceID map[string]*ResourceBuffer
}

func NewBuffer() *Buffer {
	return &Buffer{
		scopesByResourceID: make(map[string]*ResourceBuffer),
	}
}

func (b *Buffer) Insert(resource *ResourceInfo, scope *ScopeInfo, span *tracev1.Span) {
	resourceEq := resource.ID()
	var scopes *ResourceBuffer
	if sc, ok := b.scopesByResourceID[resourceEq]; ok {
		scopes = sc
	} else {
		scopes = NewResourceBuffer(resource)
		b.scopesByResourceID[resourceEq] = scopes
	}
	scopes.Insert(scope, span)
}

func (b *Buffer) Flush() []*tracev1.ResourceSpans {
	out := make([]*tracev1.ResourceSpans, 0, len(b.scopesByResourceID))
	for _, key := range slices.Sorted(maps.Keys(b.scopesByResourceID)) {
		scopes := b.scopesByResourceID[key]
		resourceSpans := &tracev1.ResourceSpans{
			Resource:   scopes.resource.Resource,
			ScopeSpans: scopes.Flush(),
			SchemaUrl:  scopes.resource.Schema,
		}
		out = append(out, resourceSpans)
	}
	clear(b.scopesByResourceID)
	return out
}

func (b *Buffer) Merge(other *Buffer) {
	if b != nil {
		for k, otherV := range other.scopesByResourceID {
			if v, ok := b.scopesByResourceID[k]; !ok {
				b.scopesByResourceID[k] = otherV
			} else {
				v.Merge(otherV)
			}
		}
	}
	clear(other.scopesByResourceID)
}

func (b *Buffer) IsEmpty() bool {
	return len(b.scopesByResourceID) == 0
}

type ResourceInfo struct {
	Resource *resourcev1.Resource
	Schema   string
	ID       func() string
}

func NewResourceInfo(resource *resourcev1.Resource, resourceSchema string) *ResourceInfo {
	ri := &ResourceInfo{
		Resource: resource,
		Schema:   resourceSchema,
	}
	ri.ID = sync.OnceValue(ri.computeID)
	return ri
}

func (ri *ResourceInfo) computeID() string {
	hash := hashutil.NewDigest()
	tmp := resourcev1.Resource{
		Attributes: ri.Resource.Attributes,
	}
	bytes, _ := proto.Marshal(&tmp)
	hash.WriteStringWithLen(ri.Schema)
	hash.WriteWithLen(bytes)
	return base64.StdEncoding.EncodeToString(hash.Sum(nil))
}

type ScopeInfo struct {
	Scope  *commonv1.InstrumentationScope
	Schema string
	ID     func() string
}

func NewScopeInfo(scope *commonv1.InstrumentationScope, scopeSchema string) *ScopeInfo {
	si := &ScopeInfo{
		Scope:  scope,
		Schema: scopeSchema,
	}
	si.ID = sync.OnceValue(si.computeID)
	return si
}

func (si *ScopeInfo) computeID() string {
	if si.Scope == nil {
		return "(unknown)"
	}
	hash := hashutil.NewDigest()
	tmp := commonv1.InstrumentationScope{
		Name:       si.Scope.Name,
		Version:    si.Scope.Version,
		Attributes: si.Scope.Attributes,
	}
	bytes, _ := proto.Marshal(&tmp)
	hash.WriteStringWithLen(si.Schema)
	hash.WriteWithLen(bytes)
	return base64.StdEncoding.EncodeToString(hash.Sum(nil))
}
