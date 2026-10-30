package sink

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	healthv2 "github.com/pomerium/pomerium/pkg/health/v2"
	"github.com/pomerium/pomerium/pkg/health/v2/check"
)

// goldenSnapshot is equivalent to the v1 state the testdata/http_*.json files were captured from.
func goldenSnapshot(group check.Group) healthv2.Snapshot {
	return healthv2.Snapshot{Configured: true, Checkers: []healthv2.CheckerStatus{
		checkerStatus(group, "core",
			running("a"),
			check.Result{Name: "b", Status: check.StatusTerminating, Attrs: []check.Attr{{Key: "foo", Value: "bar"}}},
			failing("c", check.StatusUnknown, "some error"),
		),
		checkerStatus(group, "d", check.Result{Name: "d"}),
	}}
}

func httpWith(snap healthv2.Snapshot) *HTTP {
	h := NewHTTP()
	h.Notify(snap)
	return h
}

func serve(h http.HandlerFunc, method string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(method, "/", nil))
	return rec
}

func TestHTTPWireCompat(t *testing.T) {
	t.Parallel()

	sink := httpWith(goldenSnapshot(""))
	for _, tc := range []struct {
		golden  string
		handler http.HandlerFunc
		code    int
	}{
		{"http_status.json", sink.Status, http.StatusOK},
		{"http_startup.json", sink.StartupProbe, http.StatusServiceUnavailable},
		{"http_ready.json", sink.ReadyProbe, http.StatusServiceUnavailable},
		{"http_live.json", sink.LivenessProbe, http.StatusServiceUnavailable},
	} {
		t.Run(tc.golden, func(t *testing.T) {
			t.Parallel()
			rec := serve(tc.handler, http.MethodGet)
			assert.Equal(t, tc.code, rec.Code)
			assert.JSONEq(t, string(readGolden(t, tc.golden)), rec.Body.String())
		})
	}
}

func TestHTTPProbeCodes(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name                 string
		snap                 healthv2.Snapshot
		started, ready, live int
	}{
		{
			name:    "running",
			snap:    snapshotOf(running("a")),
			started: http.StatusOK, ready: http.StatusOK, live: http.StatusOK,
		},
		{
			name:    "terminating",
			snap:    snapshotOf(terminating("a")),
			started: http.StatusOK, ready: http.StatusServiceUnavailable, live: http.StatusOK,
		},
		{
			name:    "running with error",
			snap:    snapshotOf(failing("a", check.StatusRunning, "x")),
			started: http.StatusOK, ready: http.StatusServiceUnavailable, live: http.StatusServiceUnavailable,
		},
		{
			name:    "not configured",
			snap:    healthv2.Snapshot{},
			started: http.StatusServiceUnavailable, ready: http.StatusServiceUnavailable, live: http.StatusServiceUnavailable,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			sink := httpWith(tc.snap)
			assert.Equal(t, tc.started, serve(sink.StartupProbe, http.MethodGet).Code, "startup")
			assert.Equal(t, tc.ready, serve(sink.ReadyProbe, http.MethodGet).Code, "ready")
			assert.Equal(t, tc.live, serve(sink.LivenessProbe, http.MethodGet).Code, "live")

			head := serve(sink.ReadyProbe, http.MethodHead)
			assert.Equal(t, tc.ready, head.Code)
			assert.Empty(t, head.Body.String())
		})
	}
}

func TestHTTPStatusGroup(t *testing.T) {
	t.Parallel()

	rec := serve(httpWith(goldenSnapshot(check.GroupProxy)).Status, http.MethodGet)
	require.Equal(t, http.StatusOK, rec.Code)

	var payload httpStatusPayload
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	for name, entry := range payload.Statuses {
		assert.Equal(t, string(check.GroupProxy), entry.Group, name)
	}
}

func TestHTTPMethodNotAllowed(t *testing.T) {
	t.Parallel()

	sink := NewHTTP()
	for _, method := range []string{
		http.MethodConnect,
		http.MethodDelete,
		http.MethodOptions,
		http.MethodPatch,
		http.MethodPost,
		http.MethodPut,
		http.MethodTrace,
	} {
		for _, h := range []http.HandlerFunc{sink.Status, sink.StartupProbe, sink.ReadyProbe, sink.LivenessProbe} {
			assert.Equal(t, http.StatusMethodNotAllowed, serve(h, method).Code, method)
		}
	}
}
