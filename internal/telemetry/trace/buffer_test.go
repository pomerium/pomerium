package trace_test

import (
	"encoding/binary"
	"fmt"
	"testing"
	"unique"

	"github.com/pomerium/pomerium/internal/telemetry/trace"
	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/stretchr/testify/assert"
	oteltrace "go.opentelemetry.io/otel/trace"
	commonv1 "go.opentelemetry.io/proto/otlp/common/v1"
	resourcev1 "go.opentelemetry.io/proto/otlp/resource/v1"
	tracev1 "go.opentelemetry.io/proto/otlp/trace/v1"
)

type (
	Trace    uint32
	Span     uint32
	Scope    uint32
	Schema   uint32
	Resource uint32
)

func (n Trace) String() string    { return fmt.Sprintf("Trace %d", n) }
func (n Span) String() string     { return fmt.Sprintf("Span %d", n) }
func (n Scope) String() string    { return fmt.Sprintf("Scope %d", n) }
func (n Schema) String() string   { return fmt.Sprintf("Schema %d", n) }
func (n Resource) String() string { return fmt.Sprintf("Resource %d", n) }

func (n Trace) ID() unique.Handle[oteltrace.TraceID] {
	id, _ := trace.ToTraceID(n.B())
	return id
}

func (n Trace) B() []byte {
	var id oteltrace.TraceID
	binary.BigEndian.PutUint32(id[12:], uint32(n))
	return id[:]
}

func (n Span) ID() oteltrace.SpanID {
	id, _ := trace.ToSpanID(n.B())
	return id
}

func (n Span) B() []byte {
	var id oteltrace.SpanID
	binary.BigEndian.PutUint32(id[4:], uint32(n))
	return id[:]
}

func (n Scope) Make(s ...Schema) *trace.ScopeInfo {
	if len(s) == 0 {
		s = append(s, Schema(0))
	}
	return trace.NewScopeInfo(&commonv1.InstrumentationScope{
		Name:    n.String(),
		Version: "v1",
		Attributes: []*commonv1.KeyValue{
			{
				Key: "id",
				Value: &commonv1.AnyValue{
					Value: &commonv1.AnyValue_IntValue{
						IntValue: int64(n),
					},
				},
			},
		},
	}, s[0].String())
}

func (n Resource) Make(s ...Schema) *trace.ResourceInfo {
	if len(s) == 0 {
		s = append(s, Schema(0))
	}
	return trace.NewResourceInfo(&resourcev1.Resource{
		Attributes: []*commonv1.KeyValue{
			{
				Key: "name",
				Value: &commonv1.AnyValue{
					Value: &commonv1.AnyValue_StringValue{
						StringValue: n.String(),
					},
				},
			},
			{
				Key: "id",
				Value: &commonv1.AnyValue{
					Value: &commonv1.AnyValue_IntValue{
						IntValue: int64(n),
					},
				},
			},
		},
	}, s[0].String())
}

func Traceparent(trace Trace, span Span, sampled bool) string {
	sampledStr := "00"
	if sampled {
		sampledStr = "01"
	}
	return fmt.Sprintf("00-%s-%s-%s", trace.ID().Value(), span.ID(), sampledStr)
}

func TestBuffer(t *testing.T) {
	t.Parallel()

	// start time determines sort order of spans within a resource+scope group
	s := []*tracev1.Span{
		{TraceId: Trace(1).B(), SpanId: Span(1).B(), StartTimeUnixNano: 1},
		{TraceId: Trace(1).B(), SpanId: Span(2).B(), StartTimeUnixNano: 2},
		{TraceId: Trace(2).B(), SpanId: Span(3).B(), StartTimeUnixNano: 3},
		{TraceId: Trace(2).B(), SpanId: Span(4).B(), StartTimeUnixNano: 4},
		{TraceId: Trace(1).B(), SpanId: Span(5).B(), StartTimeUnixNano: 5},
		{TraceId: Trace(1).B(), SpanId: Span(6).B(), StartTimeUnixNano: 6},
		{TraceId: Trace(2).B(), SpanId: Span(7).B(), StartTimeUnixNano: 7},
		{TraceId: Trace(2).B(), SpanId: Span(8).B(), StartTimeUnixNano: 8},
		{TraceId: Trace(1).B(), SpanId: Span(9).B(), StartTimeUnixNano: 9},
		{TraceId: Trace(1).B(), SpanId: Span(10).B(), StartTimeUnixNano: 10},
		{TraceId: Trace(2).B(), SpanId: Span(11).B(), StartTimeUnixNano: 11},
		{TraceId: Trace(2).B(), SpanId: Span(12).B(), StartTimeUnixNano: 12},
		{TraceId: Trace(1).B(), SpanId: Span(13).B(), StartTimeUnixNano: 13},
		{TraceId: Trace(1).B(), SpanId: Span(14).B(), StartTimeUnixNano: 14},
		{TraceId: Trace(2).B(), SpanId: Span(15).B(), StartTimeUnixNano: 15},
		{TraceId: Trace(2).B(), SpanId: Span(16).B(), StartTimeUnixNano: 16},
	}

	newTestBuffer := func() *trace.Buffer {
		b := trace.NewBuffer()
		b.Insert(Resource(1).Make(), Scope(1).Make(), s[0])
		b.Insert(Resource(1).Make(), Scope(1).Make(), s[1])
		b.Insert(Resource(1).Make(), Scope(1).Make(), s[2])
		b.Insert(Resource(1).Make(), Scope(1).Make(), s[3])
		b.Insert(Resource(1).Make(), Scope(2).Make(), s[4])
		b.Insert(Resource(1).Make(), Scope(2).Make(), s[5])
		b.Insert(Resource(1).Make(), Scope(2).Make(), s[6])
		b.Insert(Resource(1).Make(), Scope(2).Make(), s[7])
		b.Insert(Resource(2).Make(), Scope(1).Make(), s[8])
		b.Insert(Resource(2).Make(), Scope(1).Make(), s[9])
		b.Insert(Resource(2).Make(), Scope(1).Make(), s[10])
		b.Insert(Resource(2).Make(), Scope(1).Make(), s[11])
		b.Insert(Resource(2).Make(), Scope(2).Make(), s[12])
		b.Insert(Resource(2).Make(), Scope(2).Make(), s[13])
		b.Insert(Resource(2).Make(), Scope(2).Make(), s[14])
		b.Insert(Resource(2).Make(), Scope(2).Make(), s[15])
		return b
	}

	newExpectedSpans := func() []*tracev1.ResourceSpans {
		return []*tracev1.ResourceSpans{
			{
				Resource: Resource(1).Make().Resource,
				ScopeSpans: []*tracev1.ScopeSpans{
					{
						Scope:     Scope(1).Make().Scope,
						Spans:     []*tracev1.Span{s[0], s[1], s[2], s[3]},
						SchemaUrl: Schema(0).String(),
					},
					{
						Scope:     Scope(2).Make().Scope,
						Spans:     []*tracev1.Span{s[4], s[5], s[6], s[7]},
						SchemaUrl: Schema(0).String(),
					},
				},
				SchemaUrl: Schema(0).String(),
			},
			{
				Resource: Resource(2).Make().Resource,
				ScopeSpans: []*tracev1.ScopeSpans{
					{
						Scope:     Scope(1).Make().Scope,
						Spans:     []*tracev1.Span{s[8], s[9], s[10], s[11]},
						SchemaUrl: Schema(0).String(),
					},
					{
						Scope:     Scope(2).Make().Scope,
						Spans:     []*tracev1.Span{s[12], s[13], s[14], s[15]},
						SchemaUrl: Schema(0).String(),
					},
				},
				SchemaUrl: Schema(0).String(),
			},
		}
	}
	t.Run("Flush", func(t *testing.T) {
		b := newTestBuffer()
		actual := b.Flush()
		assert.True(t, b.IsEmpty())
		testutil.AssertProtoEqual(t, newExpectedSpans(), actual)
	})
	t.Run("FlushAs", func(t *testing.T) {
		b := newTestBuffer()
		actual := b.FlushAs(Trace(100).ID())
		assert.True(t, b.IsEmpty())
		expected := newExpectedSpans()
		for _, resourceSpans := range expected {
			for _, scopeSpans := range resourceSpans.ScopeSpans {
				for _, span := range scopeSpans.Spans {
					span.TraceId = Trace(100).B()
				}
			}
		}
		testutil.AssertProtoEqual(t, expected, actual)
	})

	t.Run("Default scope", func(t *testing.T) {
		b := trace.NewBuffer()
		b.Insert(Resource(1).Make(Schema(2)), trace.NewScopeInfo(nil, ""), s[0])
		b.Insert(Resource(1).Make(Schema(2)), trace.NewScopeInfo(nil, ""), s[1])
		b.Insert(Resource(1).Make(Schema(2)), trace.NewScopeInfo(nil, ""), s[2])
		actual := b.Flush()
		testutil.AssertProtoEqual(t, []*tracev1.ResourceSpans{
			{
				Resource: Resource(1).Make(Schema(2)).Resource,
				ScopeSpans: []*tracev1.ScopeSpans{
					{
						Scope:     nil,
						Spans:     []*tracev1.Span{s[0], s[1], s[2]},
						SchemaUrl: "",
					},
				},
				SchemaUrl: Schema(2).String(),
			},
		}, actual)
	})
}
