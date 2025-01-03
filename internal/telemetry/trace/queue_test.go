package trace_test

import (
	"bytes"
	"context"
	"embed"
	"fmt"
	"io/fs"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pomerium/pomerium/internal/telemetry/trace"
	"github.com/pomerium/pomerium/internal/telemetry/trace/mock_otlptrace"
	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	oteltrace "go.opentelemetry.io/otel/trace"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonv1 "go.opentelemetry.io/proto/otlp/common/v1"
	tracev1 "go.opentelemetry.io/proto/otlp/trace/v1"
	"go.uber.org/mock/gomock"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

//go:embed testdata
var testdata embed.FS

func TestSpanExportQueue_Replay(t *testing.T) {
	for _, tc := range []struct {
		name  string
		file  string
		check func(t testing.TB, inputs, outputs *testutil.TraceResults)
	}{
		{
			name: "single trace",
			file: "testdata/recording_01_single_trace.json",
			check: func(t testing.TB, inputs, outputs *testutil.TraceResults) {
				inputs.AssertEqual(t, outputs)
			},
		},
		{
			name: "rewriting multiple traces",
			file: "testdata/recording_02_multi_trace.json",
			check: func(t testing.TB, inputs, outputs *testutil.TraceResults) {
				inputTraces := inputs.GetTraces().WithoutErrors()
				outputTraces := outputs.GetTraces().WithoutErrors()

				// find upstream trace
				var inputUpstreamTrace, outputUpstreamTrace *testutil.TraceDetails
				isUpstreamTrace := func(v *testutil.TraceDetails) bool {
					if strings.HasPrefix(v.Name, "Envoy: ingress:") {
						for _, attr := range v.Spans[0].Raw.Attributes {
							if attr.Key == "http.url" {
								if regexp.MustCompile(`https://127\.0\.0\.1:\d+/foo`).MatchString(attr.Value.GetStringValue()) {
									return true
								}
							}
						}
					}
					return false
				}
				for _, v := range inputTraces.ByID {
					if isUpstreamTrace(v) {
						inputUpstreamTrace = v
						break
					}
				}
				for _, v := range outputTraces.ByID {
					if isUpstreamTrace(v) {
						outputUpstreamTrace = v
						break
					}
				}
				equal, diff := inputUpstreamTrace.Equal(outputUpstreamTrace)
				if !equal {
					assert.Failf(t, "upstream traces not equal:\n%s", diff)
					return
				}

				// find downstream traces
				// should be composed of:
				// - 'ingress: GET foo.localhost.pomerium.io:<port>/foo'
				// - 'internal: GET authenticate.localhost.pomerium.io:<port>/.pomerium/sign_in' (unauthorized)
				// - 'internal: GET authenticate.localhost.pomerium.io:<port>/oauth2/callback'
				// - 'internal: GET authenticate.localhost.pomerium.io:<port>/.pomerium/sign_in' (authorized)
				// - 'internal: GET foo.localhost.pomerium.io:<port>/.pomerium/callback/'
				envoyOutputTraces := outputTraces.ByParticipant["Envoy"]
				// there should be two
				require.Len(t, envoyOutputTraces, 2)
				// find which one is not the upstream trace
				var downstreamTrace *testutil.TraceDetails
				if envoyOutputTraces[0].ID == outputUpstreamTrace.ID {
					downstreamTrace = envoyOutputTraces[1]
				} else {
					downstreamTrace = envoyOutputTraces[0]
				}
				tree := downstreamTrace.SpanTree()
				require.Empty(t, tree.DetachedParents)
				parts := tree.Root.Children
				require.Len(t, parts, 5)
				assert.True(t, regexp.MustCompile(`ingress: GET foo\.localhost\.pomerium\.io:\d+/foo`).MatchString(parts[0].Span.Raw.Name))
				assert.True(t, regexp.MustCompile(`internal: GET authenticate\.localhost\.pomerium\.io:\d+/.pomerium/sign_in`).MatchString(parts[1].Span.Raw.Name))
				assert.True(t, regexp.MustCompile(`internal: GET authenticate\.localhost\.pomerium\.io:\d+/oauth2/callback`).MatchString(parts[2].Span.Raw.Name))
				assert.True(t, regexp.MustCompile(`internal: GET authenticate\.localhost\.pomerium\.io:\d+/.pomerium/sign_in`).MatchString(parts[3].Span.Raw.Name))
				assert.True(t, regexp.MustCompile(`internal: GET foo\.localhost\.pomerium\.io:\d+/.pomerium/callback`).MatchString(parts[4].Span.Raw.Name))
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockClient := mock_otlptrace.NewMockClient(ctrl)
			var resultsMu sync.Mutex
			outputSpans := [][]*tracev1.ResourceSpans{}
			mockClient.EXPECT().
				UploadTraces(gomock.Any(), gomock.Any()).
				DoAndReturn(func(_ context.Context, protoSpans []*tracev1.ResourceSpans) error {
					resultsMu.Lock()
					defer resultsMu.Unlock()
					outputSpans = append(outputSpans, protoSpans)
					return nil
				}).
				AnyTimes()
			recording1, err := fs.ReadFile(testdata, tc.file)
			require.NoError(t, err)

			rec, err := testutil.LoadEventRecording(recording1)
			require.NoError(t, err)

			ctx := trace.Options{
				DebugFlags: trace.TrackAllSpans | trace.WarnOnIncompleteSpans | trace.WarnOnIncompleteTraces | trace.WarnOnUnresolvedReferences,
			}.NewContext(context.Background())
			queue := trace.NewSpanExportQueue(ctx, mockClient)

			recCloned := rec.Clone()

			err = rec.Replay(func(ctx context.Context, req *coltracepb.ExportTraceServiceRequest) (*coltracepb.ExportTraceServiceResponse, error) {
				return &coltracepb.ExportTraceServiceResponse{}, queue.Enqueue(ctx, req)
			})
			assert.NoError(t, err)

			// wait for all calls to UploadTraces to complete
			ctx, ca := context.WithTimeout(context.Background(), 1*time.Second)
			defer ca()
			assert.NoError(t, queue.Close(ctx))

			recCloned.Normalize(rec.NormalizedTo())

			inputRequests := []*coltracepb.ExportTraceServiceRequest{}
			for _, ev := range recCloned.Events() {
				inputRequests = append(inputRequests, ev.Request)
			}
			inputs := testutil.NewTraceResults(testutil.FlattenExportRequests(inputRequests))
			outputs := testutil.NewTraceResults(testutil.FlattenResourceSpans(outputSpans))
			tc.check(t, inputs, outputs)
		})
	}
}

func TestSpanExportQueue_Enqueue(t *testing.T) {
	type (
		mapped struct {
			s Span
			t Trace
		}
		action struct {
			exports []Span
			uploads []any // int|mapped|*tracev1.Span
		}
		testCase struct {
			name    string
			spans   []*tracev1.Span // note: span ids are set automatically by index
			actions []action
			// if actionSets is present, repeats the same test case for each entry
			actionSets [][]action
		}
	)

	traceparent := func(trace Trace, span Span, sampled ...bool) *commonv1.KeyValue {
		if len(sampled) == 0 {
			sampled = append(sampled, true)
		}
		return &commonv1.KeyValue{
			Key: "pomerium.traceparent",
			Value: &commonv1.AnyValue{Value: &commonv1.AnyValue_StringValue{
				StringValue: Traceparent(trace, span, sampled[0]),
			}},
		}
	}
	externalParent := func(span Span) *commonv1.KeyValue {
		return &commonv1.KeyValue{
			Key: "pomerium.external-parent-span",
			Value: &commonv1.AnyValue{Value: &commonv1.AnyValue_StringValue{
				StringValue: span.ID().String(),
			}},
		}
	}
	attrs := func(kvs ...*commonv1.KeyValue) []*commonv1.KeyValue { return kvs }

	cases := []testCase{
		{
			name: "single trace",
			spans: []*tracev1.Span{
				// |<========>| Span 1
				// | <======> | Span 2
				// |  <====>  | Span 3
				// T123456789A-
				Span(1): {
					TraceId:           Trace(1).B(),
					ParentSpanId:      nil,
					StartTimeUnixNano: 1,
					EndTimeUnixNano:   0xA,
				},
				Span(2): {
					TraceId:           Trace(1).B(),
					ParentSpanId:      Span(1).B(),
					StartTimeUnixNano: 2,
					EndTimeUnixNano:   9,
				},
				Span(3): {
					TraceId:           Trace(1).B(),
					ParentSpanId:      Span(2).B(),
					StartTimeUnixNano: 3,
					EndTimeUnixNano:   8,
				},
			},
			actionSets: [][]action{
				// root span first
				{
					{exports: []Span{1}, uploads: []any{1}},
					{exports: []Span{2, 3}, uploads: []any{2, 3}},
				},
				{
					{exports: []Span{1, 2}, uploads: []any{1, 2}},
					{exports: []Span{3}, uploads: []any{3}},
				},
				{
					{exports: []Span{1, 2, 3}, uploads: []any{1, 2, 3}},
				},
				{
					{exports: []Span{1, 3, 2}, uploads: []any{1, 2, 3}},
				},
				{
					{exports: []Span{1}, uploads: []any{1}},
					{exports: []Span{2}, uploads: []any{2}},
					{exports: []Span{3}, uploads: []any{3}},
				},
				{
					{exports: []Span{1}, uploads: []any{1}},
					{exports: []Span{3}, uploads: []any{3}},
					{exports: []Span{2}, uploads: []any{2}},
				},
				// root span last
				{
					{exports: []Span{2}, uploads: []any{}},
					{exports: []Span{3}, uploads: []any{}},
					{exports: []Span{1}, uploads: []any{1, 2, 3}},
				},
				{
					{exports: []Span{3}, uploads: []any{}},
					{exports: []Span{2}, uploads: []any{}},
					{exports: []Span{1}, uploads: []any{1, 2, 3}},
				},
				{
					{exports: []Span{2, 3}, uploads: []any{}},
					{exports: []Span{1}, uploads: []any{1, 2, 3}},
				},
				{
					{exports: []Span{3, 2}, uploads: []any{}},
					{exports: []Span{1}, uploads: []any{1, 2, 3}},
				},
				{
					{exports: []Span{3}, uploads: []any{}},
					{exports: []Span{2, 1}, uploads: []any{1, 2, 3}},
				},
				{
					{exports: []Span{2, 3, 1}, uploads: []any{1, 2, 3}},
				},
				// root span in the middle
				{
					{exports: []Span{2}, uploads: []any{}},
					{exports: []Span{1}, uploads: []any{1, 2}},
					{exports: []Span{3}, uploads: []any{3}},
				},
				{
					{exports: []Span{3}, uploads: []any{}},
					{exports: []Span{1}, uploads: []any{1, 3}},
					{exports: []Span{2}, uploads: []any{2}},
				},
				{
					{exports: []Span{3}, uploads: []any{}},
					{exports: []Span{1, 2}, uploads: []any{1, 2, 3}},
				},
				{
					{exports: []Span{2}, uploads: []any{}},
					{exports: []Span{1, 3}, uploads: []any{1, 2, 3}},
				},
			},
		},
		{
			name: "two correlated traces",
			spans: []*tracev1.Span{
				// |<=====>        | Span 1 (Trace 1)
				// | <===>         | Span 2 (Trace 1)
				// |  <=>          | Span 3 (Trace 1)
				// |       <======>| Span 4 (Trace 2)
				// |        <====> | Span 5 (Trace 2)
				// T123456789ABCDEF-
				Span(1): {
					TraceId:           Trace(1).B(),
					ParentSpanId:      nil,
					StartTimeUnixNano: 1,
					EndTimeUnixNano:   7,
				},
				Span(2): {
					TraceId:           Trace(1).B(),
					ParentSpanId:      Span(1).B(),
					StartTimeUnixNano: 2,
					EndTimeUnixNano:   6,
				},
				Span(3): {
					TraceId:           Trace(1).B(),
					ParentSpanId:      Span(2).B(),
					StartTimeUnixNano: 3,
					EndTimeUnixNano:   5,
				},
				Span(4): {
					TraceId:           Trace(2).B(),
					ParentSpanId:      nil,
					Attributes:        attrs(traceparent(Trace(1), Span(1))),
					StartTimeUnixNano: 8,
					EndTimeUnixNano:   0xF,
				},
				Span(5): {
					TraceId:           Trace(2).B(),
					ParentSpanId:      Span(4).B(),
					Attributes:        attrs(traceparent(Trace(1), Span(1))),
					StartTimeUnixNano: 9,
					EndTimeUnixNano:   0xE,
				},
			},
			actionSets: [][]action{
				0: {
					{
						exports: []Span{1, 2, 3, 4, 5},
						uploads: []any{1, 2, 3, mapped{4, Trace(1)}, mapped{5, Trace(1)}},
					},
				},
				1: {
					{exports: []Span{2, 3, 5}, uploads: []any{}},
					{
						exports: []Span{1, 4},
						uploads: []any{1, 2, 3, mapped{4, Trace(1)}, mapped{5, Trace(1)}},
					},
				},
				2: {
					{exports: []Span{2, 3, 5}, uploads: []any{}},
					{
						exports: []Span{1},
						uploads: []any{1, 2, 3},
					},
					{
						exports: []Span{4},
						uploads: []any{mapped{4, Trace(1)}, mapped{5, Trace(1)}},
					},
				},
				3: {
					{exports: []Span{2, 3, 5}, uploads: []any{}},
					{
						exports: []Span{4, 1},
						uploads: []any{1, 2, 3, mapped{4, Trace(1)}, mapped{5, Trace(1)}},
					},
				},
				4: {
					{exports: []Span{2, 3, 5}, uploads: []any{}},
					{exports: []Span{4}, uploads: []any{}}, // root span, but mapped to a pending trace
					{
						exports: []Span{1},
						uploads: []any{1, 2, 3, mapped{4, Trace(1)}, mapped{5, Trace(1)}},
					},
				},
			},
		},
		{
			name: "external parent",
			spans: []*tracev1.Span{
				// |??????????| Span 1 (external)
				// | <======> | Span 2 (internal)
				// |  <====>  | Span 3
				// T123456789A-
				Span(2): {
					TraceId:           Trace(1).B(),
					ParentSpanId:      Span(1).B(),
					StartTimeUnixNano: 2,
					EndTimeUnixNano:   9,
					Attributes:        attrs(externalParent(Span(1))),
				},
				Span(3): {
					TraceId:           Trace(1).B(),
					ParentSpanId:      Span(2).B(),
					StartTimeUnixNano: 3,
					EndTimeUnixNano:   8,
				},
			},
			actionSets: [][]action{
				{
					{exports: []Span{3}, uploads: []any{}},
					{exports: []Span{2}, uploads: []any{2, 3}},
				},
				{
					{exports: []Span{2, 3}, uploads: []any{2, 3}},
				},
				{
					{exports: []Span{3, 2}, uploads: []any{3, 2}},
				},
			},
		},
	}

	generatedCases := []testCase{}
	for _, tc := range cases {
		for i, s := range tc.spans {
			if s == nil {
				continue
			}
			s.SpanId = Span(i).B()
		}
		if len(tc.actionSets) > 0 {
			generated := []testCase{}
			for i, actions := range tc.actionSets {
				generated = append(generated, testCase{
					name:    fmt.Sprintf("%s (action set %d of %d)", tc.name, i+1, len(tc.actionSets)),
					spans:   tc.spans,
					actions: actions,
				})
			}
			generatedCases = append(generatedCases, generated...)
		} else {
			generatedCases = append(generatedCases, tc)
		}
	}
	for _, tc := range generatedCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockClient := mock_otlptrace.NewMockClient(ctrl)
			var resultsMu sync.Mutex
			outputSpans := make(chan []*tracev1.ResourceSpans, 64)
			mockClient.EXPECT().
				UploadTraces(gomock.Any(), gomock.Any()).
				DoAndReturn(func(_ context.Context, protoSpans []*tracev1.ResourceSpans) error {
					resultsMu.Lock()
					defer resultsMu.Unlock()
					outputSpans <- protoSpans
					return nil
				}).
				AnyTimes()

			ctx := trace.Options{
				DebugFlags: trace.TrackAllSpans | trace.WarnOnIncompleteSpans | trace.WarnOnIncompleteTraces | trace.WarnOnUnresolvedReferences,
			}.NewContext(context.Background())
			queue := trace.NewSpanExportQueue(ctx, mockClient)

			for actionIdx, action := range tc.actions {
				spans := []*tracev1.Span{}
				for _, idx := range action.exports {
					spans = append(spans, proto.Clone(tc.spans[idx]).(*tracev1.Span))
				}
				assert.NoError(t, queue.Enqueue(ctx, &coltracepb.ExportTraceServiceRequest{
					ResourceSpans: []*tracev1.ResourceSpans{
						{
							Resource:   Resource(1).Make().Resource,
							ScopeSpans: []*tracev1.ScopeSpans{{Scope: Scope(1).Make().Scope, Spans: spans}},
						},
					},
				}))
				if len(action.uploads) == 0 {
					for range 5 {
						runtime.Gosched()
						require.Empty(t, outputSpans)
					}
					continue
				}
				expectedSpans := &tracev1.ResourceSpans{
					Resource:   Resource(1).Make().Resource,
					ScopeSpans: []*tracev1.ScopeSpans{{Scope: Scope(1).Make().Scope}},
				}
				for _, expectedUpload := range action.uploads {
					switch up := expectedUpload.(type) {
					case int:
						expectedSpans.ScopeSpans[0].Spans = append(expectedSpans.ScopeSpans[0].Spans, tc.spans[up])
					case mapped:
						clone := proto.Clone(tc.spans[up.s]).(*tracev1.Span)
						clone.TraceId = up.t.B()
						expectedSpans.ScopeSpans[0].Spans = append(expectedSpans.ScopeSpans[0].Spans, clone)
					case *tracev1.Span:
						expectedSpans.ScopeSpans[0].Spans = append(expectedSpans.ScopeSpans[0].Spans, up)
					default:
						panic(fmt.Sprintf("test bug: unexpected type: %T", up))
					}
				}
				select {
				case resourceSpans := <-outputSpans:
					expected := testutil.NewTraceResults([]*tracev1.ResourceSpans{expectedSpans})
					actual := testutil.NewTraceResults(resourceSpans)
					actual.AssertEqual(t, expected, "action %d/%d", actionIdx+1, len(tc.actions))
				case <-time.After(1 * time.Second):
					t.Fatalf("timed out waiting for upload (action %d/%d)", actionIdx+1, len(tc.actions))
				}
			}
			if !t.Failed() {
				close(outputSpans)
				// ensure the queue is read fully
				if !assert.Empty(t, outputSpans) {
					for _, out := range <-outputSpans {
						t.Log(protojson.Format(out))
					}
				}
			}
		})
	}
}

func TestSpanObserver(t *testing.T) {
	t.Run("observe single reference", func(t *testing.T) {
		obs := trace.NewSpanObserver()
		assert.Equal(t, []oteltrace.SpanID{}, obs.XUnobservedIDs())

		obs.ObserveReference(Span(1).ID(), Span(2).ID())
		assert.Equal(t, []oteltrace.SpanID{Span(1).ID()}, obs.XUnobservedIDs())
		obs.Observe(Span(1).ID())
		assert.Equal(t, []oteltrace.SpanID{}, obs.XUnobservedIDs())
	})
	t.Run("observe multiple references", func(t *testing.T) {
		obs := trace.NewSpanObserver()

		obs.ObserveReference(Span(1).ID(), Span(2).ID())
		obs.ObserveReference(Span(1).ID(), Span(3).ID())
		obs.ObserveReference(Span(1).ID(), Span(4).ID())
		assert.Equal(t, []oteltrace.SpanID{Span(1).ID()}, obs.XUnobservedIDs())
		obs.Observe(Span(1).ID())
		assert.Equal(t, []oteltrace.SpanID{}, obs.XUnobservedIDs())
	})
	t.Run("observe before reference", func(t *testing.T) {
		obs := trace.NewSpanObserver()

		obs.Observe(Span(1).ID())
		assert.Equal(t, []oteltrace.SpanID{}, obs.XUnobservedIDs())
		obs.ObserveReference(Span(1).ID(), Span(2).ID())
		assert.Equal(t, []oteltrace.SpanID{}, obs.XUnobservedIDs())
	})

	t.Run("wait", func(t *testing.T) {
		obs := trace.NewSpanObserver()
		obs.ObserveReference(Span(1).ID(), Span(2).ID())
		obs.Observe(Span(2).ID())
		obs.ObserveReference(Span(3).ID(), Span(4).ID())
		obs.Observe(Span(4).ID())
		obs.ObserveReference(Span(5).ID(), Span(6).ID())
		obs.Observe(Span(6).ID())
		waitOkToExit := atomic.Bool{}
		waitExited := atomic.Bool{}
		go func() {
			defer waitExited.Store(true)
			obs.XWait()
			assert.True(t, waitOkToExit.Load(), "wait exited early")
		}()

		time.Sleep(10 * time.Millisecond)
		assert.False(t, waitExited.Load())

		obs.Observe(Span(1).ID())
		time.Sleep(10 * time.Millisecond)
		assert.False(t, waitExited.Load())

		obs.Observe(Span(3).ID())
		time.Sleep(10 * time.Millisecond)
		assert.False(t, waitExited.Load())

		waitOkToExit.Store(true)
		obs.Observe(Span(5).ID())
		assert.Eventually(t, waitExited.Load, 10*time.Millisecond, 1*time.Millisecond)
	})

	t.Run("new references observed during wait", func(t *testing.T) {
		obs := trace.NewSpanObserver()
		obs.ObserveReference(Span(1).ID(), Span(2).ID())
		obs.Observe(Span(2).ID())
		obs.ObserveReference(Span(3).ID(), Span(4).ID())
		obs.Observe(Span(4).ID())
		obs.ObserveReference(Span(5).ID(), Span(6).ID())
		obs.Observe(Span(6).ID())
		waitOkToExit := atomic.Bool{}
		waitExited := atomic.Bool{}
		go func() {
			defer waitExited.Store(true)
			obs.XWait()
			assert.True(t, waitOkToExit.Load(), "wait exited early")
		}()

		assert.Equal(t, []oteltrace.SpanID{Span(1).ID(), Span(3).ID(), Span(5).ID()}, obs.XUnobservedIDs())
		time.Sleep(10 * time.Millisecond)
		assert.False(t, waitExited.Load())

		obs.Observe(Span(1).ID())
		assert.Equal(t, []oteltrace.SpanID{Span(3).ID(), Span(5).ID()}, obs.XUnobservedIDs())
		time.Sleep(10 * time.Millisecond)
		assert.False(t, waitExited.Load())

		obs.Observe(Span(3).ID())
		assert.Equal(t, []oteltrace.SpanID{Span(5).ID()}, obs.XUnobservedIDs())
		time.Sleep(10 * time.Millisecond)
		assert.False(t, waitExited.Load())

		// observe a new reference
		obs.ObserveReference(Span(7).ID(), Span(8).ID())
		obs.Observe(Span(8).ID())
		assert.Equal(t, []oteltrace.SpanID{Span(5).ID(), Span(7).ID()}, obs.XUnobservedIDs())
		time.Sleep(10 * time.Millisecond)
		assert.False(t, waitExited.Load())

		obs.Observe(Span(5).ID())
		assert.Equal(t, []oteltrace.SpanID{Span(7).ID()}, obs.XUnobservedIDs())
		time.Sleep(10 * time.Millisecond)
		assert.False(t, waitExited.Load())

		waitOkToExit.Store(true)
		obs.Observe(Span(7).ID())
		assert.Equal(t, []oteltrace.SpanID{}, obs.XUnobservedIDs())
		assert.Eventually(t, waitExited.Load, 10*time.Millisecond, 1*time.Millisecond)
	})

	t.Run("multiple waiters", func(t *testing.T) {
		t.Parallel()
		obs := trace.NewSpanObserver()
		obs.ObserveReference(Span(1).ID(), Span(2).ID())
		obs.Observe(Span(2).ID())

		waitersExited := atomic.Int32{}
		for range 10 {
			go func() {
				defer waitersExited.Add(1)
				obs.XWait()
			}()
		}

		assert.Equal(t, []oteltrace.SpanID{Span(1).ID()}, obs.XUnobservedIDs())
		time.Sleep(10 * time.Millisecond)
		assert.Equal(t, int32(0), waitersExited.Load())

		obs.Observe(Span(1).ID())

		startTime := time.Now()
		for waitersExited.Load() != 10 {
			if time.Since(startTime) > 1*time.Millisecond {
				t.Fatal("timed out")
			}
			runtime.Gosched()
		}
	})
}

func TestSpanTracker(t *testing.T) {
	t.Run("no debug flags", func(t *testing.T) {
		t.Parallel()
		obs := trace.NewSpanObserver()
		tracker := trace.NewSpanTracker(obs, 0)
		tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(tracker))
		tracer := tp.Tracer("test")
		assert.Equal(t, []oteltrace.SpanID{}, tracker.XInflightSpans())
		_, span1 := tracer.Start(context.Background(), "span 1")
		assert.Equal(t, []oteltrace.SpanID{span1.SpanContext().SpanID()}, tracker.XInflightSpans())
		assert.Equal(t, []oteltrace.SpanID{}, obs.XObservedIDs())
		span1.End()
		assert.Equal(t, []oteltrace.SpanID{}, tracker.XInflightSpans())
		assert.Equal(t, []oteltrace.SpanID{}, obs.XObservedIDs())
	})
	t.Run("with TrackSpanReferences debug flag", func(t *testing.T) {
		t.Parallel()
		obs := trace.NewSpanObserver()
		tracker := trace.NewSpanTracker(obs, trace.TrackSpanReferences)
		tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(tracker))
		tracer := tp.Tracer("test")
		assert.Equal(t, []oteltrace.SpanID{}, tracker.XInflightSpans())
		_, span1 := tracer.Start(context.Background(), "span 1")
		assert.Equal(t, []oteltrace.SpanID{span1.SpanContext().SpanID()}, tracker.XInflightSpans())
		assert.Equal(t, []oteltrace.SpanID{span1.SpanContext().SpanID()}, obs.XObservedIDs())
		span1.End()
		assert.Equal(t, []oteltrace.SpanID{}, tracker.XInflightSpans())
		assert.Equal(t, []oteltrace.SpanID{span1.SpanContext().SpanID()}, obs.XObservedIDs())
	})
}

func TestSpanTrackerWarnings(t *testing.T) {
	t.Run("WarnOnIncompleteSpans", func(t *testing.T) {
		var buf bytes.Buffer
		trace.SetDebugMessageWriterForTest(t, &buf)

		obs := trace.NewSpanObserver()
		tracker := trace.NewSpanTracker(obs, trace.WarnOnIncompleteSpans)
		tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(tracker))
		tracer := tp.Tracer("test")
		_, span1 := tracer.Start(context.Background(), "span 1")

		assert.ErrorIs(t, tp.Shutdown(context.Background()), trace.ErrIncompleteSpans)

		assert.Equal(t, fmt.Sprintf(`
==================================================
WARNING: spans not ended:
%s
Note: set TrackAllSpans flag for more info
==================================================
`, span1.SpanContext().SpanID()), buf.String())
	})

	t.Run("WarnOnIncompleteSpans with TrackAllSpans", func(t *testing.T) {
		var buf bytes.Buffer
		trace.SetDebugMessageWriterForTest(t, &buf)

		obs := trace.NewSpanObserver()
		tracker := trace.NewSpanTracker(obs, trace.WarnOnIncompleteSpans|trace.TrackAllSpans)
		tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(tracker))
		tracer := tp.Tracer("test")
		_, span1 := tracer.Start(context.Background(), "span 1")

		assert.ErrorIs(t, tp.Shutdown(context.Background()), trace.ErrIncompleteSpans)

		assert.Equal(t, fmt.Sprintf(`
==================================================
WARNING: spans not ended:
'span 1' (trace: %s | span: %s | parent: 0000000000000000)
==================================================
`, span1.SpanContext().TraceID(), span1.SpanContext().SpanID()), buf.String())
	})

	t.Run("WarnOnIncompleteSpans with TrackAllSpans and stackTraceProcessor", func(t *testing.T) {
		var buf bytes.Buffer
		trace.SetDebugMessageWriterForTest(t, &buf)

		obs := trace.NewSpanObserver()
		tracker := trace.NewSpanTracker(obs, trace.WarnOnIncompleteSpans|trace.TrackAllSpans)
		tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(&trace.XStackTraceProcessor{}), sdktrace.WithSpanProcessor(tracker))
		tracer := tp.Tracer("test")
		_, span1 := tracer.Start(context.Background(), "span 1")
		_, file, line, _ := runtime.Caller(0)
		line--

		assert.ErrorIs(t, tp.Shutdown(context.Background()), trace.ErrIncompleteSpans)

		assert.Equal(t, fmt.Sprintf(`
==================================================
WARNING: spans not ended:
'span 1' (trace: %s | span: %s | parent: 0000000000000000 | started at: %s:%d)
==================================================
`, span1.SpanContext().TraceID(), span1.SpanContext().SpanID(), file, line), buf.String())
	})

	t.Run("LogAllSpansOnWarn", func(t *testing.T) {
		var buf bytes.Buffer
		trace.SetDebugMessageWriterForTest(t, &buf)

		obs := trace.NewSpanObserver()
		tracker := trace.NewSpanTracker(obs, trace.WarnOnIncompleteSpans|trace.TrackAllSpans|trace.LogAllSpansOnWarn)
		tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(&trace.XStackTraceProcessor{}), sdktrace.WithSpanProcessor(tracker))
		tracer := tp.Tracer("test")
		_, span1 := tracer.Start(context.Background(), "span 1")
		time.Sleep(10 * time.Millisecond)
		span1.End()
		time.Sleep(10 * time.Millisecond)
		_, span2 := tracer.Start(context.Background(), "span 2")
		_, file, line, _ := runtime.Caller(0)
		line--

		tp.Shutdown(context.Background())

		assert.Equal(t,
			fmt.Sprintf(`
==================================================
WARNING: spans not ended:
'span 2' (trace: %[1]s | span: %[2]s | parent: 0000000000000000 | started at: %[3]s:%[4]d)
==================================================

==================================================
All observed spans:
'span 1' (trace: %[5]s | span: %[6]s | parent: 0000000000000000 | started at: %[3]s:%[7]d)
'span 2' (trace: %[1]s | span: %[2]s | parent: 0000000000000000 | started at: %[3]s:%[4]d)
==================================================
`,
				span2.SpanContext().TraceID(), span2.SpanContext().SpanID(), file, line,
				span1.SpanContext().TraceID(), span1.SpanContext().SpanID(), line-4,
			), buf.String())
	})
}
