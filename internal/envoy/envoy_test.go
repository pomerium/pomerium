package envoy

import (
	"fmt"
	"net/url"
	"testing"

	envoy_config_bootstrap_v3 "github.com/envoyproxy/go-control-plane/envoy/config/bootstrap/v3"
	"github.com/golang/protobuf/proto"
	"github.com/nsf/jsondiff"
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
