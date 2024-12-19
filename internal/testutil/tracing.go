package testutil

import (
	"cmp"
	"fmt"
	"maps"
	"slices"
	"sync"
	"testing"
	"time"
	"unique"

	"github.com/pomerium/pomerium/internal/telemetry/trace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	oteltrace "go.opentelemetry.io/otel/trace"
	commonv1 "go.opentelemetry.io/proto/otlp/common/v1"
	resourcev1 "go.opentelemetry.io/proto/otlp/resource/v1"
	tracev1 "go.opentelemetry.io/proto/otlp/trace/v1"
)

type TraceResults struct {
	resourceSpans []*tracev1.ResourceSpans

	GetResources func() []*resourcev1.Resource
	GetTraces    func() *Traces
}

type Traces struct {
	ByID   map[unique.Handle[oteltrace.TraceID]]*TraceDetails
	ByName map[string][]*TraceDetails
}

type TraceDetails struct {
	ID        unique.Handle[oteltrace.TraceID]
	Name      string
	Spans     []*SpanDetails
	Services  []string
	StartTime time.Time
	EndTime   time.Time
	Duration  time.Duration
}

func (td *TraceDetails) SpanTree() *SpanTree {
	nodesById := map[oteltrace.SpanID]*SpanTreeNode{}
	nodesById[oteltrace.SpanID([8]byte{})] = &SpanTreeNode{} // root node
	for _, span := range td.Spans {
		spanId, _ := trace.ToSpanID(span.Raw.SpanId)
		nodesById[spanId] = &SpanTreeNode{
			Span: span,
		}
	}
	detachedNodesById := map[oteltrace.SpanID]*SpanTreeNode{}
	for _, span := range td.Spans {
		spanId, _ := trace.ToSpanID(span.Raw.SpanId)
		parentSpanId, _ := trace.ToSpanID(span.Raw.ParentSpanId)
		if _, ok := nodesById[parentSpanId]; !ok {
			detachedNodesById[parentSpanId] = &SpanTreeNode{}
			nodesById[parentSpanId] = detachedNodesById[parentSpanId]
		}
		nodesById[spanId].Parent = nodesById[parentSpanId]
		nodesById[parentSpanId].Children = append(nodesById[parentSpanId].Children, nodesById[spanId])
	}
	for _, node := range nodesById {
		slices.SortFunc(node.Children, func(a, b *SpanTreeNode) int {
			return cmp.Compare(a.Span.Raw.StartTimeUnixNano, b.Span.Raw.StartTimeUnixNano)
		})
	}
	return &SpanTree{
		Root:            nodesById[oteltrace.SpanID([8]byte{})],
		DetachedParents: detachedNodesById,
	}
}

type SpanDetails struct {
	Raw       *tracev1.Span
	Resource  *resourcev1.Resource
	Scope     *commonv1.InstrumentationScope
	StartTime time.Time
	EndTime   time.Time
	Duration  time.Duration
	Service   string
}

func NewTraceResults(resourceSpans []*tracev1.ResourceSpans) *TraceResults {
	tr := &TraceResults{
		resourceSpans: resourceSpans,
	}
	tr.GetResources = sync.OnceValue(tr.computeResources)
	tr.GetTraces = sync.OnceValue(tr.computeTraces)
	return tr
}

func (tr *TraceResults) computeResources() []*resourcev1.Resource {
	resources := []*resourcev1.Resource{}
	for _, res := range tr.resourceSpans {
		resources = append(resources, res.Resource)
	}
	return resources
}

func (tr *TraceResults) computeTraces() *Traces {
	tracesById := map[unique.Handle[oteltrace.TraceID]]*TraceDetails{}
	for _, resSpan := range tr.resourceSpans {
		resource := resSpan.Resource
		for _, scopeSpans := range resSpan.ScopeSpans {
			scope := scopeSpans.Scope
			for _, span := range scopeSpans.Spans {
				traceId, _ := trace.ToTraceID(span.TraceId)
				var details *TraceDetails
				if d, ok := tracesById[traceId]; ok {
					details = d
				} else {
					details = &TraceDetails{
						ID: traceId,
					}
					tracesById[traceId] = details
				}
				svc := ""
				for _, attr := range resource.Attributes {
					if attr.Key == "service.name" {
						svc = attr.Value.GetStringValue()
						break
					}
				}
				details.Spans = append(details.Spans, &SpanDetails{
					Raw:       span,
					Resource:  resource,
					Scope:     scope,
					StartTime: time.Unix(0, int64(span.StartTimeUnixNano)),
					EndTime:   time.Unix(0, int64(span.EndTimeUnixNano)),
					Duration:  time.Duration(span.EndTimeUnixNano - span.StartTimeUnixNano),
					Service:   svc,
				})
			}
		}
	}

	tracesByName := map[string][]*TraceDetails{}

	// sort spans by start time and compute durations
	for _, td := range tracesById {
		slices.SortFunc(td.Spans, func(a, b *SpanDetails) int {
			return cmp.Compare(a.Raw.StartTimeUnixNano, b.Raw.StartTimeUnixNano)
		})
		startTime := td.Spans[0].Raw.StartTimeUnixNano
		endTime := td.Spans[0].Raw.EndTimeUnixNano
		serviceNames := map[string]struct{}{}
		for _, span := range td.Spans {
			startTime = min(startTime, span.Raw.StartTimeUnixNano)
			endTime = max(endTime, span.Raw.EndTimeUnixNano)
			if span.Service != "" {
				serviceNames[span.Service] = struct{}{}
			}
		}
		td.StartTime = time.Unix(0, int64(startTime))
		td.EndTime = time.Unix(0, int64(endTime))
		td.Duration = td.EndTime.Sub(td.StartTime)
		td.Services = slices.Sorted(maps.Keys(serviceNames))
		td.Name = fmt.Sprintf("%s: %s", td.Spans[0].Service, td.Spans[0].Raw.Name)
		tracesByName[td.Name] = append(tracesByName[td.Name], td)
	}

	return &Traces{
		ByID:   tracesById,
		ByName: tracesByName,
	}
}

type SpanTree struct {
	Root            *SpanTreeNode
	DetachedParents map[oteltrace.SpanID]*SpanTreeNode
}

type SpanTreeNode struct {
	Span     *SpanDetails
	Parent   *SpanTreeNode
	Children []*SpanTreeNode
}

type Match struct {
	Name       string
	TraceCount any
	Services   []string
}

type (
	GreaterOrEqual int
	Greater        int

	// Any makes no assertions on the trace count. If the trace is not found, it
	// doesn't count against the Exact match option.
	Any struct{}

	// Asserts that the value is the same as the value of another match (by name)
	SameAs string
)

type MatchOptions struct {
	// If true, asserts that there is exactly one [Match] entry per result
	Exact bool
	// If true, asserts that no traces contain detached spans
	CheckDetachedSpans bool
}

func (tr *TraceResults) MatchTraces(t testing.TB, opts MatchOptions, matches ...Match) {
	t.Helper()
	traces := tr.GetTraces()
	matchArgsByName := map[string]Match{}
	for i, m := range matches {
		if m.Name != "" {
			require.NotContains(t, matchArgsByName, m.Name, "duplicate name")
			matchArgsByName[m.Name] = m
			if traceDetails, ok := traces.ByName[m.Name]; ok {
				switch tc := m.TraceCount.(type) {
				case GreaterOrEqual:
					assert.GreaterOrEqualf(t, len(traceDetails), int(tc),
						"[match %d]: expected %q to have >=%d traces, but found %d",
						i+1, m.Name, int(tc), len(traceDetails))
				case Greater:
					assert.Greaterf(t, len(traceDetails), int(tc),
						"[match %d]: expected %q to have >%d traces, but found %d",
						i+1, m.Name, int(tc), len(traceDetails))
				case SameAs:
					assert.Equalf(t, len(traceDetails), len(traces.ByName[string(tc)]),
						"[match %d]: expected %q to have %d traces (equivalent to %s), but found %d",
						i+1, m.Name, len(traces.ByName[string(tc)]), string(tc), len(traceDetails))
				case Any:
				case int:
					s := "s"
					if tc == 1 {
						s = ""
					}
					assert.Lenf(t, traceDetails, tc,
						"[match %d]: expected %q to have %d trace%s, but found %d",
						i+1, m.Name, tc, s, len(traceDetails))
				}

				if m.Services != nil {
					for _, trace := range traceDetails {
						assert.ElementsMatch(t, m.Services, trace.Services)
					}
				}
			} else if _, ok := m.TraceCount.(Any); !ok {
				t.Errorf("no traces with name %q found", m.Name)
			}
		}
	}
	if opts.CheckDetachedSpans {
		for _, trace := range traces.ByID {
			tree := trace.SpanTree()
			assert.Empty(t, tree.DetachedParents)
		}
	}
	if opts.Exact {
		expected := slices.Sorted(maps.Keys(matchArgsByName))
		actual := slices.Sorted(maps.Keys(traces.ByName))
		for name, match := range matchArgsByName {
			if _, ok := traces.ByName[name]; !ok {
				if _, ok := match.TraceCount.(Any); ok {
					expected = slices.DeleteFunc(expected, func(s string) bool { return s == name })
				}
			}
		}
		assert.Equal(t, expected, actual)
	}
}
