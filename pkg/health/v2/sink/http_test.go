package sink

import (
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	healthv2 "github.com/pomerium/pomerium/pkg/health/v2"
)

func goldenSnapshot() healthv2.Snapshot {
	return snapshotOf(
		checkerStatus("a", pass(map[string]string{"role": "leader"}), pass(nil)),
		checkerStatus("b", healthv2.Condition{Info: healthv2.Info{Reason: "syncing", Details: map[string]string{"foo": "bar"}}}, pass(nil)),
		checkerStatus("c", healthv2.Condition{OK: true, Info: healthv2.Info{Reason: "stale"}}, fail("some error")),
		uninitialized(checkerStatus("d", pass(nil), pass(map[string]string{"k": "v"})), "loading"),
	)
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

func TestHTTPGolden(t *testing.T) {
	t.Parallel()

	sink := httpWith(goldenSnapshot())
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
			name:    "starting",
			snap:    snapshotOf(uninitialized(running("a"), "loading")),
			started: http.StatusServiceUnavailable, ready: http.StatusServiceUnavailable, live: http.StatusOK,
		},
		{
			name:    "not_ready",
			snap:    snapshotOf(checkerStatus("a", fail("syncing"), pass(nil))),
			started: http.StatusOK, ready: http.StatusServiceUnavailable, live: http.StatusOK,
		},
		{
			name:    "unhealthy",
			snap:    snapshotOf(checkerStatus("a", pass(nil), fail("boom"))),
			started: http.StatusOK, ready: http.StatusOK, live: http.StatusServiceUnavailable,
		},
		{
			name:    "empty",
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

func TestHTTPStatusKeys(t *testing.T) {
	t.Parallel()

	rec := serve(httpWith(goldenSnapshot()).Status, http.MethodGet)
	require.Equal(t, http.StatusOK, rec.Code)

	var payload httpStatusPayload
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	assert.Equal(t, []string{"Proxy/a", "Proxy/b", "Proxy/c", "Proxy/d"}, payload.Checks)
	assert.Equal(t, payload.Checks, slices.Sorted(maps.Keys(payload.Statuses)))
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
