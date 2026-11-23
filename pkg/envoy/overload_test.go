package envoy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/pkg/health"
	"github.com/pomerium/pomerium/pkg/netutil"
)

func TestOverloadReadiness(t *testing.T) {
	for _, tc := range []struct {
		name      string
		stats     string
		statsCode int
		readyCode int
		wantError string
		wantReady int
		wantLive  int
	}{
		{
			name: "healthy",
			stats: `{"stats":[
				{"name":"overload.envoy.overload_actions.stop_accepting_connections.active","value":0},
				{"name":"overload.envoy.overload_actions.stop_accepting_requests.active","value":0}
			]}`,
			wantReady: http.StatusOK, wantLive: http.StatusOK,
		},
		{
			name:      "connections stopped",
			stats:     `{"stats":[{"name":"overload.envoy.overload_actions.stop_accepting_connections.active","value":1}]}`,
			wantError: "stop_accepting_connections.active is active",
			wantReady: http.StatusServiceUnavailable, wantLive: http.StatusOK,
		},
		{
			name:      "requests stopped",
			stats:     `{"stats":[{"name":"overload.envoy.overload_actions.stop_accepting_requests.active","value":1}]}`,
			wantError: "stop_accepting_requests.active is active",
			wantReady: http.StatusServiceUnavailable, wantLive: http.StatusOK,
		},
		{
			name: "no configured actions", stats: `{"stats":[]}`,
			wantReady: http.StatusOK, wantLive: http.StatusOK,
		},
		{
			name:      "other overload actions do not affect readiness",
			stats:     `{"stats":[{"name":"overload.envoy.overload_actions.shrink_heap.active","value":1}]}`,
			wantReady: http.StatusOK, wantLive: http.StatusOK,
		},
		{
			name: "stats unavailable", statsCode: http.StatusServiceUnavailable,
			wantError: "overload stats endpoint: 503",
			wantReady: http.StatusServiceUnavailable, wantLive: http.StatusOK,
		},
		{
			name: "invalid stats", stats: `{"stats":[`,
			wantError: "decoding envoy overload actions",
			wantReady: http.StatusServiceUnavailable, wantLive: http.StatusOK,
		},
		{
			name: "missing stats", stats: `{}`,
			wantError: "missing envoy overload stats",
			wantReady: http.StatusServiceUnavailable, wantLive: http.StatusOK,
		},
		{
			name:      "missing value",
			stats:     `{"stats":[{"name":"overload.envoy.overload_actions.stop_accepting_connections.active"}]}`,
			wantError: "missing envoy overload stat value",
			wantReady: http.StatusServiceUnavailable, wantLive: http.StatusOK,
		},
		{
			name: "envoy not ready", readyCode: http.StatusServiceUnavailable,
			wantReady: http.StatusServiceUnavailable, wantLive: http.StatusServiceUnavailable,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/ready":
					if tc.readyCode != 0 {
						w.WriteHeader(tc.readyCode)
					}
					_, _ = io.WriteString(w, "LIVE\n")
				case "/stats":
					assert.Equal(t, "json", r.URL.Query().Get("format"))
					filter, err := regexp.Compile(r.URL.Query().Get("filter"))
					if !assert.NoError(t, err) {
						return
					}
					assert.True(t, filter.MatchString("overload.envoy.overload_actions.stop_accepting_connections.active"))
					assert.True(t, filter.MatchString("overload.envoy.overload_actions.stop_accepting_requests.active"))
					assert.False(t, filter.MatchString("overload.envoy.overload_actions.shrink_heap.active"))
					if tc.statsCode != 0 {
						w.WriteHeader(tc.statsCode)
					}
					_, _ = io.WriteString(w, tc.stats)
				default:
					t.Errorf("unexpected admin request: %s", r.URL)
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer admin.Close()

			srv := newTestAdminServer(admin)
			mgr := health.NewManager()
			checks := append([]health.Check{health.EnvoyServer}, srv.GetExpectedHealthChecks()...)
			probes := health.NewHTTPProvider(mgr, health.WithExpectedChecks(checks...))
			srv.reportReadiness(t.Context(), mgr)

			for _, probe := range []struct {
				handler http.HandlerFunc
				code    int
			}{
				{probes.ReadyProbe, tc.wantReady},
				{probes.LivenessProbe, tc.wantLive},
			} {
				rec := httptest.NewRecorder()
				probe.handler(rec, httptest.NewRequest(http.MethodGet, "/", nil))
				assert.Equal(t, probe.code, rec.Code, rec.Body.String())
				if tc.wantError != "" && probe.code == http.StatusServiceUnavailable {
					assert.Contains(t, rec.Body.String(), tc.wantError)
				}
			}
			if tc.wantLive == http.StatusOK {
				rec := httptest.NewRecorder()
				probes.StartupProbe(rec, httptest.NewRequest(http.MethodGet, "/", nil))
				assert.Equal(t, http.StatusOK, rec.Code)
			}
		})
	}
}

func TestOverloadRecovery(t *testing.T) {
	var overloaded atomic.Bool
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ready" {
			_, _ = io.WriteString(w, "LIVE\n")
			return
		}
		value := "0"
		if overloaded.Load() {
			value = "1"
		}
		_, _ = io.WriteString(w, `{"stats":[{"name":"overload.envoy.overload_actions.stop_accepting_connections.active","value":`+value+`}]}`)
	}))
	defer admin.Close()

	srv := newTestAdminServer(admin)
	mgr := health.NewManager()
	probes := health.NewHTTPProvider(mgr, health.WithExpectedChecks(health.EnvoyServer, health.EnvoyOverload))
	for _, state := range []bool{false, true, false} {
		overloaded.Store(state)
		srv.reportReadiness(t.Context(), mgr)
		rec := httptest.NewRecorder()
		probes.ReadyProbe(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
		want := http.StatusOK
		if state {
			want = http.StatusServiceUnavailable
		}
		assert.Equal(t, want, rec.Code, rec.Body.String())
	}
}

func TestOverloadCanceled(t *testing.T) {
	admin := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer admin.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	require.ErrorIs(t, newTestAdminServer(admin).envoyOverload(ctx), context.DeadlineExceeded)
}

func newTestAdminServer(admin *httptest.Server) *Server {
	return &Server{ServerOptions: ServerOptions{
		adminAddress: *netutil.NewInternalAddressForTCP(netip.MustParseAddrPort(strings.TrimPrefix(admin.URL, "http://"))),
	}}
}
