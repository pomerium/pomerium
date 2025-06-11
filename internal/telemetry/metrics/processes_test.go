package metrics

import (
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opencensus.io/stats/view"
)

func TestProcessCollector(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.SkipNow()
	}

	exp, err := getGlobalExporter()
	require.NoError(t, err)

	pc := NewProcessCollector("example")
	err = view.Register(pc.Views()...)
	require.NoError(t, err)
	defer view.Unregister(pc.Views()...)

	err = pc.Measure(t.Context(), os.Getpid())
	require.NoError(t, err)

	expect := []string{
		"pomerium_example_process_cpu_seconds_total",
		"pomerium_example_process_max_fds",
		"pomerium_example_process_open_fds",
		"pomerium_example_process_resident_memory_bytes",
		"pomerium_example_process_start_time_seconds",
		"pomerium_example_process_virtual_memory_bytes",
		"pomerium_example_process_virtual_memory_max_bytes",
	}
	assert.Eventually(t, func() bool {
		req := httptest.NewRequest(http.MethodGet, "http://test.local/metrics", nil)
		rec := httptest.NewRecorder()
		exp.ServeHTTP(rec, req)
		str := rec.Body.String()
		for _, nm := range expect {
			if !strings.Contains(str, nm) {
				return false
			}
		}
		return true
	}, time.Second*3, time.Millisecond*50,
		"prometheus exporter should contain process metrics: %v",
		expect)
}
