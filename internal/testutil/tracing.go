package testutil

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"unique"

	gocmp "github.com/google/go-cmp/cmp"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	oteltrace "go.opentelemetry.io/otel/trace"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonv1 "go.opentelemetry.io/proto/otlp/common/v1"
	resourcev1 "go.opentelemetry.io/proto/otlp/resource/v1"
	tracev1 "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
)

type TraceResults struct {
	resourceSpans []*tracev1.ResourceSpans

	GetResources func() []*resourcev1.Resource
	GetTraces    func() *Traces
}

type Traces struct {
	ByID          map[unique.Handle[oteltrace.TraceID]]*TraceDetails
	ByName        map[string]TraceDetailsList
	ByParticipant map[string]TraceDetailsList
}

func (t *Traces) WithoutErrors() *Traces {
	byID := make(map[unique.Handle[oteltrace.TraceID]]*TraceDetails, len(t.ByID))
	for k, v := range t.ByID {
		if len(v.Errors) > 0 {
			continue
		}
		byID[k] = v
	}
	byName := make(map[string]TraceDetailsList)
	for k, v := range t.ByName {
		filtered := v.WithoutErrors()
		if len(filtered) == 0 {
			continue
		}
		byName[k] = filtered
	}
	byParticipant := make(map[string]TraceDetailsList)
	for k, v := range t.ByParticipant {
		filtered := v.WithoutErrors()
		if len(filtered) == 0 {
			continue
		}
		byParticipant[k] = filtered
	}
	return &Traces{
		ByID:          byID,
		ByName:        byName,
		ByParticipant: byParticipant,
	}
}

type TraceDetails struct {
	ID        unique.Handle[oteltrace.TraceID]
	Name      string
	Spans     []*SpanDetails
	Services  []string
	StartTime time.Time
	EndTime   time.Time
	Duration  time.Duration
	Errors    []int // indexes into Spans
}

func (td *TraceDetails) Equal(other *TraceDetails) (bool, string) {
	diffSpans := func(a, b []*SpanDetails) (bool, string) {
		for i := range len(a) {
			aRaw := proto.Clone(a[i].Raw).(*tracev1.Span)
			trace.FormatSpanName(aRaw)
			bRaw := proto.Clone(b[i].Raw).(*tracev1.Span)
			trace.FormatSpanName(bRaw)
			diff := gocmp.Diff(aRaw, bRaw, protocmp.Transform())
			if diff != "" {
				return false, diff
			}
		}
		return true, ""
	}
	if td.ID != other.ID {
		return false, fmt.Sprintf("traces are trivially not equal: ID %s (actual) != %s (expected)", td.ID.Value(), other.ID.Value())
	}
	if len(td.Spans) != len(other.Spans) {
		return false, fmt.Sprintf("traces are trivially not equal: len(spans) %d (actual) != %d (expected)", len(td.Spans), len(other.Spans))
	}
	if !td.StartTime.Equal(other.StartTime) {
		return false, fmt.Sprintf("traces are trivially not equal: start time %s (actual) != %s (expected)", td.StartTime, other.StartTime)
	}
	if !td.EndTime.Equal(other.EndTime) {
		return false, fmt.Sprintf("traces are trivially not equal: end time %s (actual) != %s (expected)", td.EndTime, other.EndTime)
	}
	return diffSpans(td.Spans, other.Spans)
}

type TraceDetailsList []*TraceDetails

func (list TraceDetailsList) WithoutExportRPCs() TraceDetailsList {
	out := make(TraceDetailsList, 0, len(list))
	for _, td := range list {
		if strings.Contains(td.Name, "opentelemetry.proto.collector.trace.v1.TraceService/Export") {
			continue
		}
		out = append(out, td)
	}
	return out
}

func (list TraceDetailsList) WithoutErrors() TraceDetailsList {
	out := make(TraceDetailsList, 0, len(list))
	for _, td := range list {
		if len(td.Errors) > 0 {
			continue
		}
		out = append(out, td)
	}
	return out
}

func (td *TraceDetails) SpanTree() *SpanTree {
	nodesByID := map[oteltrace.SpanID]*SpanTreeNode{}
	nodesByID[oteltrace.SpanID([8]byte{})] = &SpanTreeNode{} // root node
	for _, span := range td.Spans {
		spanID, _ := trace.ToSpanID(span.Raw.SpanId)
		nodesByID[spanID] = &SpanTreeNode{
			Span: span,
		}
	}
	detachedNodesByID := map[oteltrace.SpanID]*SpanTreeNode{}
	for _, span := range td.Spans {
		spanID, _ := trace.ToSpanID(span.Raw.SpanId)
		parentSpanID, _ := trace.ToSpanID(span.Raw.ParentSpanId)
		if _, ok := nodesByID[parentSpanID]; !ok {
			detachedNodesByID[parentSpanID] = &SpanTreeNode{}
			nodesByID[parentSpanID] = detachedNodesByID[parentSpanID]
		}
		nodesByID[spanID].Parent = nodesByID[parentSpanID]
		nodesByID[parentSpanID].Children = append(nodesByID[parentSpanID].Children, nodesByID[spanID])
	}
	for _, node := range nodesByID {
		slices.SortFunc(node.Children, func(a, b *SpanTreeNode) int {
			return cmp.Compare(a.Span.Raw.StartTimeUnixNano, b.Span.Raw.StartTimeUnixNano)
		})
	}
	return &SpanTree{
		Root:            nodesByID[oteltrace.SpanID([8]byte{})],
		DetachedParents: detachedNodesByID,
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
	tracesByID := map[unique.Handle[oteltrace.TraceID]]*TraceDetails{}
	for _, resSpan := range tr.resourceSpans {
		resource := resSpan.Resource
		for _, scopeSpans := range resSpan.ScopeSpans {
			scope := scopeSpans.Scope
			for _, span := range scopeSpans.Spans {
				traceID, _ := trace.ToTraceID(span.TraceId)
				var details *TraceDetails
				if d, ok := tracesByID[traceID]; ok {
					details = d
				} else {
					details = &TraceDetails{
						ID: traceID,
					}
					tracesByID[traceID] = details
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
				if span.Status != nil {
					if span.Status.Code == tracev1.Status_STATUS_CODE_ERROR {
						details.Errors = append(details.Errors, len(details.Spans)-1)
					}
				}
			}
		}
	}

	tracesByName := map[string]TraceDetailsList{}
	tracesByParticipant := map[string]TraceDetailsList{}
	// sort spans by start time and compute durations
	for _, td := range tracesByID {
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
		for svc := range serviceNames {
			tracesByParticipant[svc] = append(tracesByParticipant[svc], td)
		}
	}

	return &Traces{
		ByID:          tracesByID,
		ByName:        tracesByName,
		ByParticipant: tracesByParticipant,
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

	// EqualToMatch asserts that the value is the same as the value of another
	// match (by name)
	EqualToMatch string
	// GreaterThanMatch asserts that the value is greater than the value of
	// another match (by name)
	GreaterThanMatch string
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
				case GreaterThanMatch:
					assert.Greaterf(t, len(traceDetails), len(traces.ByName[string(tc)]),
						"[match %d]: expected %q to have >%d traces (value of %s), but found %d",
						i+1, m.Name, len(traces.ByName[string(tc)]), string(tc), len(traceDetails))
				case EqualToMatch:
					assert.Equalf(t, len(traceDetails), len(traces.ByName[string(tc)]),
						"[match %d]: expected %q to have %d traces (value of %s), but found %d",
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
			if !assert.Empty(t, tree.DetachedParents) {
				for spanID, node := range tree.DetachedParents {
					t.Log("------------------------------------")
					t.Logf("span id: %s", spanID)
					if len(node.Children) != 0 {
						t.Log("children:")
					}
					for _, c := range node.Children {
						t.Log(protojson.Format(c.Span.Raw))
					}
					t.Log("------------------------------------")
				}
			}
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

func (tr *TraceResults) AssertEqual(t testing.TB, expectedResults *TraceResults, msgFmtAndArgs ...any) {
	t.Helper()
	actualTraces := tr.GetTraces()
	expectedTraces := expectedResults.GetTraces()
	for traceID, expected := range expectedTraces.ByID {
		if actual, ok := actualTraces.ByID[traceID]; !ok {
			if len(msgFmtAndArgs) > 0 {
				t.Errorf("expected trace id %s not found (%s)", traceID.Value().String(),
					fmt.Sprintf(msgFmtAndArgs[0].(string), msgFmtAndArgs[1:]...))
			} else {
				t.Errorf("expected trace id %s not found", traceID.Value().String())
			}
		} else {
			if equal, diff := actual.Equal(expected); !equal {
				if len(msgFmtAndArgs) > 0 {
					t.Errorf("trace %s is not equal (%s):\n%s", traceID.Value().String(),
						fmt.Sprintf(msgFmtAndArgs[0].(string), msgFmtAndArgs[1:]...), diff)
				} else {
					t.Errorf("trace %s is not equal:\n%s", traceID.Value().String(), diff)
				}
			}
		}
	}
	for traceID := range actualTraces.ByID {
		if _, ok := expectedTraces.ByID[traceID]; !ok {
			if len(msgFmtAndArgs) > 0 {
				t.Errorf("unexpected trace id %s found (%s)", traceID.Value().String(),
					fmt.Sprintf(msgFmtAndArgs[0].(string), msgFmtAndArgs[1:]...))
			} else {
				t.Errorf("unexpected trace id %s found", traceID.Value().String())
			}
		}
	}
}

func FlattenResourceSpans(lists [][]*tracev1.ResourceSpans) []*tracev1.ResourceSpans {
	res := trace.NewBuffer()
	for _, list := range lists {
		for _, resource := range list {
			resInfo := trace.NewResourceInfo(resource.Resource, resource.SchemaUrl)
			for _, scope := range resource.ScopeSpans {
				scopeInfo := trace.NewScopeInfo(scope.Scope, scope.SchemaUrl)
				for _, span := range scope.Spans {
					res.Insert(resInfo, scopeInfo, span)
				}
			}
		}
	}
	return res.Flush()
}

func FlattenExportRequests(reqs []*coltracepb.ExportTraceServiceRequest) []*tracev1.ResourceSpans {
	lists := make([][]*tracev1.ResourceSpans, len(reqs))
	for i, req := range reqs {
		lists[i] = req.ResourceSpans
	}
	return FlattenResourceSpans(lists)
}

type EventRecording struct {
	events       []trace.DebugEvent
	normalizedTo time.Time
}

func LoadEventRecording(raw []byte) (*EventRecording, error) {
	events := []trace.DebugEvent{}
	if err := json.Unmarshal(raw, &events); err != nil {
		return nil, err
	}
	for i := 1; i < len(events); i++ {
		if events[i].Timestamp.Before(events[i-1].Timestamp) {
			return nil, fmt.Errorf("invalid timestamps: event %d occurred before event %d", i, i-1)
		}
	}
	return &EventRecording{
		events: events,
	}, nil
}

func (er *EventRecording) Normalize(startTime time.Time) {
	if len(er.events) == 0 {
		return
	}
	er.normalizedTo = startTime
	offset := startTime.Sub(er.events[0].Timestamp)
	for i, ev := range er.events {
		er.events[i].Timestamp = ev.Timestamp.Add(offset)
		for _, resSpan := range ev.Request.ResourceSpans {
			for _, scopeSpans := range resSpan.ScopeSpans {
				for _, span := range scopeSpans.Spans {
					span.StartTimeUnixNano += uint64(offset)
					span.EndTimeUnixNano += uint64(offset)
					for _, event := range span.Events {
						event.TimeUnixNano += uint64(offset)
					}
				}
			}
		}
	}
}

func (er *EventRecording) NormalizedTo() time.Time {
	return er.normalizedTo
}

type EventCallbackFunc = func(ctx context.Context, req *coltracepb.ExportTraceServiceRequest) (*coltracepb.ExportTraceServiceResponse, error)

func (er *EventRecording) Events() []trace.DebugEvent {
	return er.events
}

func (er *EventRecording) Clone() *EventRecording {
	clonedEvents := make([]trace.DebugEvent, 0, len(er.events))
	for _, ev := range er.events {
		clonedEvents = append(clonedEvents, trace.DebugEvent{
			Timestamp: ev.Timestamp,
			Request:   proto.Clone(ev.Request).(*coltracepb.ExportTraceServiceRequest),
		})
	}
	c := &EventRecording{
		events:       clonedEvents,
		normalizedTo: er.normalizedTo,
	}
	return c
}

func (er *EventRecording) Replay(callback EventCallbackFunc) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	durations := make([]time.Duration, 0, len(er.events)-1)
	for i := 1; i < len(er.events); i++ {
		durations = append(durations, er.events[i].Timestamp.Sub(er.events[i-1].Timestamp))
	}

	var wg sync.WaitGroup
	wg.Add(len(er.events))
	er.Normalize(time.Now())
	for i, ev := range er.events {
		go func() {
			callback(context.Background(), ev.Request)
			wg.Done()
		}()
		if i < len(er.events)-1 {
			time.Sleep(durations[i])
		}
	}
	wg.Wait()
	return nil
}
