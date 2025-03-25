package trace_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/testenv"
	"github.com/pomerium/pomerium/internal/testenv/scenarios"
	"github.com/pomerium/pomerium/internal/testenv/snippets"
	. "github.com/pomerium/pomerium/internal/testutil/tracetest" //nolint:revive
	"github.com/pomerium/pomerium/internal/testutil/tracetest/mock_otlptrace"
	"github.com/pomerium/pomerium/internal/version"
	"github.com/pomerium/pomerium/pkg/telemetry/trace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	tracev1 "go.opentelemetry.io/proto/otlp/trace/v1"
	v1 "go.opentelemetry.io/proto/otlp/trace/v1"
	"go.uber.org/mock/gomock"
)

func TestSyncClient(t *testing.T) {
	t.Run("No client", func(t *testing.T) {
		sc := trace.NewSyncClient(nil)
		assert.ErrorIs(t, sc.Start(context.Background()), trace.ErrNoClient)
		assert.ErrorIs(t, sc.UploadTraces(context.Background(), nil), trace.ErrNoClient)
		assert.ErrorIs(t, sc.Stop(context.Background()), trace.ErrNoClient)
	})

	t.Run("Valid client", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockClient := mock_otlptrace.NewMockClient(ctrl)
		start := mockClient.EXPECT().
			Start(gomock.Any()).
			Return(nil)
		upload := mockClient.EXPECT().
			UploadTraces(gomock.Any(), gomock.Any()).
			Return(nil).
			After(start)
		mockClient.EXPECT().
			Stop(gomock.Any()).
			Return(nil).
			After(upload)
		sc := trace.NewSyncClient(mockClient)
		assert.NoError(t, sc.Start(context.Background()))
		assert.NoError(t, sc.UploadTraces(context.Background(), []*tracev1.ResourceSpans{}))
		assert.NoError(t, sc.Stop(context.Background()))
	})
	t.Run("Update", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockClient1 := mock_otlptrace.NewMockClient(ctrl)
		mockClient2 := mock_otlptrace.NewMockClient(ctrl)

		start1 := mockClient1.EXPECT().
			Start(gomock.Any()).
			Return(nil)
		upload1 := mockClient1.EXPECT().
			UploadTraces(gomock.Any(), gomock.Any()).
			Return(nil).
			After(start1)
		start2 := mockClient2.EXPECT().
			Start(gomock.Any()).
			Return(nil).
			After(upload1)
		stop1 := mockClient1.EXPECT().
			Stop(gomock.Any()).
			Return(nil).
			After(start2)
		upload2 := mockClient2.EXPECT().
			UploadTraces(gomock.Any(), gomock.Any()).
			Return(nil).
			After(stop1)
		mockClient2.EXPECT().
			Stop(gomock.Any()).
			Return(nil).
			After(upload2)
		sc := trace.NewSyncClient(mockClient1)
		assert.NoError(t, sc.Start(context.Background()))
		assert.NoError(t, sc.UploadTraces(context.Background(), []*tracev1.ResourceSpans{}))
		assert.NoError(t, sc.Update(context.Background(), mockClient2))
		assert.NoError(t, sc.UploadTraces(context.Background(), []*tracev1.ResourceSpans{}))
		assert.NoError(t, sc.Stop(context.Background()))
	})

	t.Run("Update from nil client to non-nil client", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		sc := trace.NewSyncClient(nil)

		mockClient := mock_otlptrace.NewMockClient(ctrl)
		start := mockClient.EXPECT().
			Start(gomock.Any()).
			Return(nil)
		upload := mockClient.EXPECT().
			UploadTraces(gomock.Any(), gomock.Any()).
			Return(nil).
			After(start)
		mockClient.EXPECT().
			Stop(gomock.Any()).
			Return(nil).
			After(upload)
		assert.NoError(t, sc.Update(context.Background(), mockClient))
		assert.NoError(t, sc.UploadTraces(context.Background(), []*tracev1.ResourceSpans{}))
		assert.NoError(t, sc.Stop(context.Background()))
	})

	t.Run("Update from non-nil client to nil client", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		sc := trace.NewSyncClient(nil)

		{
			mockClient := mock_otlptrace.NewMockClient(ctrl)
			start := mockClient.EXPECT().
				Start(gomock.Any()).
				Return(nil)
			mockClient.EXPECT().
				Stop(gomock.Any()).
				Return(nil).
				After(start)
			assert.NoError(t, sc.Update(context.Background(), mockClient))
		}

		sc.Update(context.Background(), nil)
		assert.ErrorIs(t, sc.UploadTraces(context.Background(), []*tracev1.ResourceSpans{}), trace.ErrNoClient)
	})

	spinWait := func(counter *atomic.Int32, until int32) error {
		startTime := time.Now()
		for counter.Load() != until {
			if time.Since(startTime) > 1*time.Second {
				return fmt.Errorf("timed out waiting for counter to equal %d", until)
			}
		}
		return nil
	}

	t.Run("Concurrent UploadTraces", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockClient1 := mock_otlptrace.NewMockClient(ctrl)
		count := atomic.Int32{}
		unlock := make(chan struct{})
		concurrency := min(runtime.NumCPU(), 4)
		mockClient1.EXPECT().
			UploadTraces(gomock.Any(), gomock.Any()).
			DoAndReturn(func(context.Context, []*tracev1.ResourceSpans) error {
				count.Add(1)
				defer count.Add(-1)
				<-unlock
				return nil
			}).
			Times(concurrency)
		sc := trace.NewSyncClient(mockClient1)
		start := make(chan struct{})
		for range concurrency {
			go func() {
				runtime.LockOSThread()
				defer runtime.UnlockOSThread()
				<-start
				require.NoError(t, sc.UploadTraces(context.Background(), []*tracev1.ResourceSpans{}))
			}()
		}

		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		close(start)
		assert.NoError(t, spinWait(&count, int32(concurrency)))
	})

	t.Run("Concurrent Update/UploadTraces", func(t *testing.T) {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		ctrl := gomock.NewController(t)
		mockClient1 := mock_otlptrace.NewMockClient(ctrl)
		mockClient2 := mock_otlptrace.NewMockClient(ctrl)
		uploadTracesCount1 := atomic.Int32{}
		uploadTracesCount2 := atomic.Int32{}
		unlock1 := make(chan struct{})
		unlock2 := make(chan struct{})
		waitForStop := make(chan struct{})
		concurrency := min(runtime.NumCPU(), 4)

		// start 1 -> upload 1 -> start 2 -> stop 1 -> upload 2 -> stop 2
		fStart1 := mockClient1.EXPECT().
			Start(gomock.Any()).
			Return(nil)
		fUpload1 := mockClient1.EXPECT().
			UploadTraces(gomock.Any(), gomock.Any()).
			DoAndReturn(func(context.Context, []*tracev1.ResourceSpans) error {
				// called from non-test threads
				uploadTracesCount1.Add(1)
				defer uploadTracesCount1.Add(-1)
				<-unlock1
				return nil
			}).
			Times(concurrency).
			After(fStart1)
		fStart2 := mockClient2.EXPECT().
			Start(gomock.Any()).
			Return(nil).
			After(fUpload1)
		fStop1 := mockClient1.EXPECT().
			Stop(gomock.Any()).
			DoAndReturn(func(context.Context) error {
				// called from test thread
				close(unlock1)
				assert.NoError(t, spinWait(&uploadTracesCount1, 0))
				return nil
			}).
			After(fStart2)
		fUpload2 := mockClient2.EXPECT().
			UploadTraces(gomock.Any(), gomock.Any()).
			DoAndReturn(func(context.Context, []*tracev1.ResourceSpans) error {
				// called from non-test threads
				uploadTracesCount2.Add(1)
				defer uploadTracesCount2.Add(-1)
				<-unlock2
				return nil
			}).
			Times(concurrency).
			After(fStop1)
		mockClient2.EXPECT().
			Stop(gomock.Any()).
			DoAndReturn(func(context.Context) error {
				// called from test thread
				close(unlock2)
				assert.NoError(t, spinWait(&uploadTracesCount2, 0))
				close(waitForStop)
				// no way around sleeping here - we have to give the other threads time
				// to call UploadTraces and block waiting on waitForNewClient to be
				// closed, which happens after this function returns
				time.Sleep(10 * time.Millisecond)
				return nil
			}).
			After(fUpload2)
		sc := trace.NewSyncClient(mockClient1)
		require.NoError(t, sc.Start(context.Background()))

		for range concurrency {
			go func() {
				require.NoError(t, sc.UploadTraces(context.Background(), []*tracev1.ResourceSpans{}))
			}()
		}
		require.NoError(t, spinWait(&uploadTracesCount1, int32(concurrency)))
		// at this point, all calls to UploadTraces for client1 are blocked

		for range concurrency {
			go func() {
				<-unlock1 // wait for client1.Stop
				// after this, calls to UploadTraces will block waiting for the
				// new client, instead of using the old one we're about to close
				require.NoError(t, sc.UploadTraces(context.Background(), []*tracev1.ResourceSpans{}))
			}()
		}
		require.NoError(t, sc.Update(context.Background(), mockClient2))
		require.NoError(t, spinWait(&uploadTracesCount2, int32(concurrency)))
		// at this point, all calls to UploadTraces for client2 are blocked.

		// while SyncClient is waiting for the underlying client to stop during
		// sc.Stop(), *new* calls to sc.UploadTraces will wait for it to stop, then
		// error with trace.ErrClientStopped, but the previous calls blocked in
		// client2 will complete without error.
		for range concurrency {
			go func() {
				<-waitForStop
				assert.ErrorIs(t, sc.UploadTraces(context.Background(), []*tracev1.ResourceSpans{}), trace.ErrClientStopped)
			}()
		}
		assert.NoError(t, sc.Stop(context.Background()))

		// sanity checks
		assert.ErrorIs(t, sc.UploadTraces(context.Background(), []*tracev1.ResourceSpans{}), trace.ErrNoClient)
		assert.ErrorIs(t, sc.Start(context.Background()), trace.ErrNoClient)
		assert.ErrorIs(t, sc.Stop(context.Background()), trace.ErrNoClient)
		assert.NoError(t, sc.Update(context.Background(), nil))
	})

	t.Run("repeated updates", func(t *testing.T) {
		sc := trace.NewSyncClient(nil)
		for range 1000 {
			sc.Update(context.Background(), &sleepClient{})
		}
	})
}

type sleepClient struct{}

// Start implements otlptrace.Client.
func (n sleepClient) Start(context.Context) error {
	time.Sleep(10 * time.Millisecond)
	return nil
}

// Stop implements otlptrace.Client.
func (n sleepClient) Stop(context.Context) error {
	time.Sleep(10 * time.Millisecond)
	return nil
}

// UploadTraces implements otlptrace.Client.
func (n sleepClient) UploadTraces(context.Context, []*v1.ResourceSpans) error {
	return nil
}

type errHandler struct {
	err error
}

var _ otel.ErrorHandler = (*errHandler)(nil)

func (h *errHandler) Handle(err error) {
	h.err = err
}

func TestNewTraceClientFromConfig(t *testing.T) {
	env := testenv.New(t, testenv.WithTraceDebugFlags(testenv.StandardTraceDebugFlags))

	receiver := scenarios.NewOTLPTraceReceiver()
	env.Add(receiver)

	grpcEndpoint := receiver.GRPCEndpointURL()
	httpEndpoint := receiver.HTTPEndpointURL()

	emptyConfigFilePath := filepath.Join(env.TempDir(), "empty_config.yaml")
	require.NoError(t, os.WriteFile(emptyConfigFilePath, []byte("{}"), 0o644))

	env.Start()
	snippets.WaitStartupComplete(env)

	for _, tc := range []struct {
		name          string
		env           map[string]string
		newClientErr  string
		uploadErr     bool
		expectNoSpans bool
		expectHeaders map[string][]string
	}{
		{
			name: "GRPC endpoint, unset protocol",
			env: map[string]string{
				"OTEL_TRACES_EXPORTER":               "otlp",
				"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": grpcEndpoint.Value(),
			},
		},
		{
			name: "GRPC endpoint, empty protocol",
			env: map[string]string{
				"OTEL_TRACES_EXPORTER":               "otlp",
				"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": grpcEndpoint.Value(),
				"OTEL_EXPORTER_OTLP_TRACES_PROTOCOL": "",
			},
		},
		{
			name: "GRPC endpoint, alternate env, unset protocol",
			env: map[string]string{
				"OTEL_TRACES_EXPORTER":        "otlp",
				"OTEL_EXPORTER_OTLP_ENDPOINT": grpcEndpoint.Value(),
			},
			uploadErr: true,
		},
		{
			name: "GRPC endpoint, alternate env, empty protocol",
			env: map[string]string{
				"OTEL_TRACES_EXPORTER":        "otlp",
				"OTEL_EXPORTER_OTLP_ENDPOINT": grpcEndpoint.Value(),
				"OTEL_EXPORTER_OTLP_PROTOCOL": "",
			},
			uploadErr: true,
		},
		{
			name: "HTTP endpoint, unset protocol",
			env: map[string]string{
				"OTEL_TRACES_EXPORTER":               "otlp",
				"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": httpEndpoint.Value(),
			},
		},
		{
			name: "HTTP endpoint, empty protocol",
			env: map[string]string{
				"OTEL_TRACES_EXPORTER":               "otlp",
				"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": httpEndpoint.Value(),
				"OTEL_EXPORTER_OTLP_TRACES_PROTOCOL": "",
			},
		},
		{
			name: "HTTP endpoint, alternate env, unset protocol",
			env: map[string]string{
				"OTEL_TRACES_EXPORTER":        "otlp",
				"OTEL_EXPORTER_OTLP_ENDPOINT": strings.TrimSuffix(httpEndpoint.Value(), "/v1/traces"), // path is added automatically by the sdk here
			},
		},
		{
			name: "HTTP endpoint, alternate env, empty protocol",
			env: map[string]string{
				"OTEL_TRACES_EXPORTER":        "otlp",
				"OTEL_EXPORTER_OTLP_ENDPOINT": strings.TrimSuffix(httpEndpoint.Value(), "/v1/traces"),
				"OTEL_EXPORTER_OTLP_PROTOCOL": "",
			},
		},
		{
			name: "GRPC endpoint, explicit protocol",
			env: map[string]string{
				"OTEL_TRACES_EXPORTER":               "otlp",
				"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": grpcEndpoint.Value(),
				"OTEL_EXPORTER_OTLP_TRACES_PROTOCOL": "grpc",
			},
		},
		{
			name: "HTTP endpoint, explicit protocol",
			env: map[string]string{
				"OTEL_TRACES_EXPORTER":               "otlp",
				"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": httpEndpoint.Value(),
				"OTEL_EXPORTER_OTLP_TRACES_PROTOCOL": "http/protobuf",
			},
		},
		{
			name: "exporter unset",
			env: map[string]string{
				"OTEL_TRACES_EXPORTER":               "",
				"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": httpEndpoint.Value(),
				"OTEL_EXPORTER_OTLP_TRACES_PROTOCOL": "http/protobuf",
			},
			expectNoSpans: true,
		},
		{
			name: "exporter noop",
			env: map[string]string{
				"OTEL_TRACES_EXPORTER":               "noop",
				"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": httpEndpoint.Value(),
				"OTEL_EXPORTER_OTLP_TRACES_PROTOCOL": "http/protobuf",
			},
			expectNoSpans: true,
		},
		{
			name: "exporter none",
			env: map[string]string{
				"OTEL_TRACES_EXPORTER":               "none",
				"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": httpEndpoint.Value(),
				"OTEL_EXPORTER_OTLP_TRACES_PROTOCOL": "http/protobuf",
			},
			expectNoSpans: true,
		},
		{
			name: "invalid exporter",
			env: map[string]string{
				"OTEL_TRACES_EXPORTER": "invalid",
			},
			newClientErr: `unknown otlp trace exporter "invalid", expected one of ["otlp", "none"]`,
		},
		{
			name: "invalid protocol",
			env: map[string]string{
				"OTEL_TRACES_EXPORTER":               "otlp",
				"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": grpcEndpoint.Value(),
				"OTEL_EXPORTER_OTLP_TRACES_PROTOCOL": "invalid",
			},
			newClientErr: `unknown otlp trace exporter protocol "invalid", expected one of ["grpc", "http/protobuf"]`,
		},
		{
			name: "valid configuration, but sdk disabled",
			env: map[string]string{
				"OTEL_TRACES_EXPORTER":               "otlp",
				"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": grpcEndpoint.Value(),
				"OTEL_EXPORTER_OTLP_TRACES_PROTOCOL": "grpc",
				"OTEL_SDK_DISABLED":                  "true",
			},
			expectNoSpans: true,
		},
		{
			name: "valid configuration, wrong value for sdk disabled env",
			env: map[string]string{
				"OTEL_TRACES_EXPORTER":               "otlp",
				"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": grpcEndpoint.Value(),
				"OTEL_EXPORTER_OTLP_TRACES_PROTOCOL": "grpc",
				"OTEL_SDK_DISABLED":                  "1", // only "true" works according to the spec
			},
		},
		{
			name: "endpoint variable precedence",
			env: map[string]string{
				"OTEL_TRACES_EXPORTER":               "otlp",
				"OTEL_EXPORTER_OTLP_ENDPOINT":        "invalid",
				"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": grpcEndpoint.Value(), // should take precedence
				"OTEL_EXPORTER_OTLP_PROTOCOL":        "grpc",
			},
		},
		{
			name: "protocol variable precedence",
			env: map[string]string{
				"OTEL_TRACES_EXPORTER":               "otlp",
				"OTEL_EXPORTER_OTLP_PROTOCOL":        "invalid",
				"OTEL_EXPORTER_OTLP_TRACES_PROTOCOL": "grpc", // should take precedence
				"OTEL_EXPORTER_OTLP_ENDPOINT":        grpcEndpoint.Value(),
			},
		},
		{
			name: "valid exporter, trace headers",
			env: map[string]string{
				"OTEL_TRACES_EXPORTER":               "otlp",
				"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": httpEndpoint.Value(),
				"OTEL_EXPORTER_OTLP_TRACES_PROTOCOL": "http/protobuf",
				"OTEL_EXPORTER_OTLP_TRACES_HEADERS":  "foo=bar,bar=baz",
			},
			expectHeaders: map[string][]string{
				"foo": {"bar"},
				"bar": {"baz"},
			},
		},
		{
			name: "valid exporter, alt headers",
			env: map[string]string{
				"OTEL_TRACES_EXPORTER":               "otlp",
				"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": httpEndpoint.Value(),
				"OTEL_EXPORTER_OTLP_TRACES_PROTOCOL": "http/protobuf",
				"OTEL_EXPORTER_OTLP_HEADERS":         "foo=bar,bar=baz",
			},
			expectHeaders: map[string][]string{
				"foo": {"bar"},
				"bar": {"baz"},
			},
		},
		{
			name: "headers variable precedence",
			env: map[string]string{
				"OTEL_TRACES_EXPORTER":               "otlp",
				"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": httpEndpoint.Value(),
				"OTEL_EXPORTER_OTLP_TRACES_PROTOCOL": "http/protobuf",
				"OTEL_EXPORTER_OTLP_HEADERS":         "a=1,b=2,c=3",
				"OTEL_EXPORTER_OTLP_TRACES_HEADERS":  "a=2,d=4",
			},
			expectHeaders: map[string][]string{
				"a": {"2"},
				"d": {"4"},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			cfg, err := config.NewFileOrEnvironmentSource(context.Background(), emptyConfigFilePath, version.FullVersion())
			require.NoError(t, err)

			remoteClient, err := trace.NewTraceClientFromConfig(cfg.GetConfig().Options.Tracing)
			if tc.newClientErr != "" {
				assert.ErrorContains(t, err, tc.newClientErr)
				return
			}
			require.NoError(t, err)

			ctx := trace.NewContext(log.Ctx(env.Context()).WithContext(context.Background()), remoteClient)

			tp := trace.NewTracerProvider(ctx, t.Name())

			_, span := tp.Tracer(trace.PomeriumCoreTracer).Start(ctx, "test span")
			span.End()

			if tc.uploadErr {
				assert.Error(t, trace.ForceFlush(ctx))
				assert.NoError(t, trace.ShutdownContext(ctx))
				return
			}
			assert.NoError(t, trace.ShutdownContext(ctx))

			if tc.expectHeaders != nil {
				for _, req := range receiver.ReceivedRequests() {
					assert.Subset(t, req.Metadata, tc.expectHeaders, "missing expected headers")
				}
			}
			results := NewTraceResults(receiver.FlushResourceSpans())
			if tc.expectNoSpans {
				results.MatchTraces(t, MatchOptions{Exact: true})
			} else {
				results.MatchTraces(t, MatchOptions{
					Exact: true,
				}, Match{Name: t.Name() + ": test span", TraceCount: 1, Services: []string{t.Name()}})
			}
		})
	}
}

func TestBestEffortProtocolFromOTLPEndpoint(t *testing.T) {
	t.Run("Well-known port numbers", func(t *testing.T) {
		assert.Equal(t, "grpc", trace.BestEffortProtocolFromOTLPEndpoint("http://127.0.0.1:4317", true))
		assert.Equal(t, "http/protobuf", trace.BestEffortProtocolFromOTLPEndpoint("http://127.0.0.1:4318", true))
	})
	t.Run("path presence", func(t *testing.T) {
		assert.Equal(t, "http/protobuf", trace.BestEffortProtocolFromOTLPEndpoint("http://127.0.0.1:12345", false))
		assert.Equal(t, "grpc", trace.BestEffortProtocolFromOTLPEndpoint("http://127.0.0.1:12345", true))
		assert.Equal(t, "grpc", trace.BestEffortProtocolFromOTLPEndpoint("http://127.0.0.1:12345/v1/traces", false))
		assert.Equal(t, "http/protobuf", trace.BestEffortProtocolFromOTLPEndpoint("http://127.0.0.1:12345/v1/traces", true))
	})
	t.Run("invalid inputs", func(t *testing.T) {
		assert.Equal(t, "", trace.BestEffortProtocolFromOTLPEndpoint("", false))
		assert.Equal(t, "", trace.BestEffortProtocolFromOTLPEndpoint("http://\x7f", false))
	})
}
