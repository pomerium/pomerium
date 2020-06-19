package envoy

import (
	"fmt"
	"io/ioutil"
	"net/url"
	"regexp"
	"strings"
	"testing"

	envoy_config_bootstrap_v3 "github.com/envoyproxy/go-control-plane/envoy/config/bootstrap/v3"
	"github.com/golang/protobuf/proto"
	"github.com/nsf/jsondiff"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/testutil"
)

func jsonDump(t *testing.T, m proto.GeneratedMessage) []byte {
	t.Helper()

	jsonBytes, err := protojson.Marshal(proto.MessageV2(m))
	if err != nil {
		t.Fatalf("failed to marshal json: %s", err)
	}
	return jsonBytes
}

func Test_addTraceConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		opts    *config.TracingOptions
		want    string
		wantErr bool
	}{
		{
			"good zipkin",
			&config.TracingOptions{Provider: config.ZipkinTracingProviderName, ZipkinEndpoint: &url.URL{Host: "localhost:9411"}},
			`{"tracing":{"http":{"name":"envoy.tracers.opencensus","typedConfig":{"@type":"type.googleapis.com/envoy.config.trace.v3.OpenCensusConfig","zipkinExporterEnabled":true,"zipkinUrl":"//localhost:9411","incomingTraceContext":["B3","TRACE_CONTEXT","CLOUD_TRACE_CONTEXT","GRPC_TRACE_BIN"],"outgoingTraceContext":["B3","TRACE_CONTEXT","GRPC_TRACE_BIN"]}}}}`,
			false,
		},
		{
			"good jaeger",
			&config.TracingOptions{Provider: config.JaegerTracingProviderName},
			`{}`,
			false,
		},
		{
			"bad zipkin",
			&config.TracingOptions{Provider: config.ZipkinTracingProviderName, ZipkinEndpoint: &url.URL{}},
			`{}`,
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := &Server{}
			baseCfg := &envoy_config_bootstrap_v3.Bootstrap{}

			err := srv.addTraceConfig(tt.opts, baseCfg)

			assert.Equal(t, tt.wantErr, err != nil, "unexpected error state")

			diff, diffStr := jsondiff.Compare([]byte(tt.want), jsonDump(t, baseCfg), &jsondiff.Options{})
			assert.Equal(t, jsondiff.FullMatch, diff, fmt.Sprintf("%s: differences: %s", diff.String(), diffStr))
		})
	}
}

func Test_buildStatsConfig(t *testing.T) {
	tests := []struct {
		name string
		opts *config.Options
		want string
	}{
		{"all-in-one", &config.Options{Services: config.ServiceAll}, `{"statsTags":[{"tagName":"service","fixedValue":"pomerium"}]}`},
		{"authorize", &config.Options{Services: config.ServiceAuthorize}, `{"statsTags":[{"tagName":"service","fixedValue":"pomerium-authorize"}]}`},
		{"proxy", &config.Options{Services: config.ServiceProxy}, `{"statsTags":[{"tagName":"service","fixedValue":"pomerium-proxy"}]}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := &Server{opts: tt.opts}

			statsCfg := srv.buildStatsConfig()
			testutil.AssertProtoJSONEqual(t, tt.want, statsCfg)
		})
	}
}

func TestServer_handleLogs(t *testing.T) {
	logFormatRE := regexp.MustCompile(`^[[]LOG_FORMAT[]](.*?)--(.*?)--(.*?)$`)
	line := "[LOG_FORMAT]debug--filter--[external/envoy/source/extensions/filters/listener/tls_inspector/tls_inspector.cc:78] tls inspector: new connection accepted"
	old := func(s string) string {
		msg := s
		parts := logFormatRE.FindStringSubmatch(s)
		if len(parts) == 4 {
			msg = parts[3]
		}
		return msg
	}
	srv := &Server{}
	expectedMsg := old(line)
	name, logLevel, gotMsg := srv.parseLog(line)
	if name != "filter" {
		t.Errorf("unexpected name, want filter, got: %s", name)
	}
	if logLevel != "debug" {
		t.Errorf("unexpected log level, want debug, got: %s", logLevel)
	}
	if gotMsg != expectedMsg {
		t.Errorf("unexpected msg, want %s, got: %s", expectedMsg, gotMsg)
	}
}

func Benchmark_handleLogs(b *testing.B) {
	line := `[LOG_FORMAT]debug--http--[external/envoy/source/common/http/conn_manager_impl.cc:781] [C25][S14758077654018620250] request headers complete (end_stream=false):\\n\\':authority\\', \\'enabled-ws-echo.localhost.pomerium.io\\'\\n\\':path\\', \\'/\\'\\n\\':method\\', \\'GET\\'\\n\\'upgrade\\', \\'websocket\\'\\n\\'connection\\', \\'upgrade\\'\\n\\'x-request-id\\', \\'30ac7726e0b9e00a9c9ab2bf66d692ac\\'\\n\\'x-real-ip\\', \\'172.17.0.1\\'\\n\\'x-forwarded-for\\', \\'172.17.0.1\\'\\n\\'x-forwarded-host\\', \\'enabled-ws-echo.localhost.pomerium.io\\'\\n\\'x-forwarded-port\\', \\'443\\'\\n\\'x-forwarded-proto\\', \\'https\\'\\n\\'x-scheme\\', \\'https\\'\\n\\'user-agent\\', \\'Go-http-client/1.1\\'\\n\\'sec-websocket-key\\', \\'4bh7+YFVzrJiblaSu/CVfg==\\'\\n\\'sec-websocket-version\\', \\'13\\'`
	rc := ioutil.NopCloser(strings.NewReader(line))
	srv := &Server{}
	zerolog.SetGlobalLevel(zerolog.InfoLevel)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		srv.handleLogs(rc)
	}
}
