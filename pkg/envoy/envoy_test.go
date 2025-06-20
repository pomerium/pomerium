package envoy

import (
	"io"
	"regexp"
	"strings"
	"testing"

	"github.com/rs/zerolog"
)

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
	rc := io.NopCloser(strings.NewReader(line))
	srv := &Server{}
	zerolog.SetGlobalLevel(zerolog.InfoLevel)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		srv.handleLogs(b.Context(), rc)
	}
}
