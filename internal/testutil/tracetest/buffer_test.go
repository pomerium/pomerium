package tracetest

import (
	"testing"

	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/stretchr/testify/assert"
	tracev1 "go.opentelemetry.io/proto/otlp/trace/v1"
)

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

	newTestBuffer := func() *Buffer {
		b := NewBuffer()
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

	t.Run("Default scope", func(t *testing.T) {
		b := NewBuffer()
		b.Insert(Resource(1).Make(Schema(2)), NewScopeInfo(nil, ""), s[0])
		b.Insert(Resource(1).Make(Schema(2)), NewScopeInfo(nil, ""), s[1])
		b.Insert(Resource(1).Make(Schema(2)), NewScopeInfo(nil, ""), s[2])
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
