package envoyconfig_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/testenv"
	"github.com/pomerium/pomerium/internal/testenv/snippets"
	"github.com/pomerium/pomerium/internal/testenv/upstreams"
	"github.com/pomerium/pomerium/internal/testenv/values"
	"github.com/pomerium/pomerium/pkg/envoy"
	"github.com/pomerium/pomerium/pkg/netutil"
)

// TestWebsocketViaMiddleEnvoy covers the topology where Pomerium runs in
// front of a second L7 proxy (e.g. Envoy Gateway) that then forwards to a
// WebSocket backend. See ENG-4018.
//
// Three cases:
//
//  1. middle Envoy has upgrade_configs: websocket and Pomerium has
//     allow_websockets: true. The chain works.
//  2. middle Envoy is missing upgrade_configs. Envoy refuses the upgrade.
//  3. Pomerium route has remove_request_headers: [Connection, Upgrade].
//     Pomerium's own Envoy strips the upgrade headers before they leave.
func TestWebsocketViaMiddleEnvoy(t *testing.T) {
	cases := []struct {
		name                      string
		middleAllowsUpgrade       bool
		pomeriumRemoveHdrs        []string
		expectClientSuccess       bool
		expectClientStatus        int // checked when expectClientSuccess is false
		expectBackendUpgrade      bool
		expectBackendSawMiddleHop bool
	}{
		{
			name:                      "middle envoy with upgrade",
			middleAllowsUpgrade:       true,
			expectClientSuccess:       true,
			expectBackendUpgrade:      true,
			expectBackendSawMiddleHop: true,
		},
		{
			// Middle Envoy refuses the upgrade with 403 (Envoy's documented
			// behaviour when an HTTP/1.1 upgrade request hits a route/HCM
			// without upgrade_configs). Asserting the status pins the fact
			// that middle Envoy was the one rejecting; a startup failure
			// would surface as 503 from Pomerium instead.
			name:                      "middle envoy without upgrade",
			middleAllowsUpgrade:       false,
			expectClientSuccess:       false,
			expectClientStatus:        http.StatusForbidden,
			expectBackendUpgrade:      false,
			expectBackendSawMiddleHop: false,
		},
		{
			// Pomerium's Envoy still treats this as an upgrade attempt at
			// HCM time, but Connection/Upgrade are stripped before the
			// request reaches the upstream cluster. The middle hop
			// receives a plain GET, so the response back to Pomerium is
			// not a 101, and Pomerium tears the downstream connection
			// down without relaying an HTTP response. The client sees an
			// aborted handshake (no status). Status 0 distinguishes this
			// from a missing-upstream failure (which would return 503).
			name:                      "pomerium remove_request_headers",
			middleAllowsUpgrade:       true,
			pomeriumRemoveHdrs:        []string{"Connection", "Upgrade"},
			expectClientSuccess:       false,
			expectClientStatus:        0,
			expectBackendUpgrade:      false,
			expectBackendSawMiddleHop: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := testenv.New(t)

			up := upstreams.HTTP(nil)
			var sawUpgrade, sawMiddleHopMarker atomic.Bool
			up.Handle("/ws", func(w http.ResponseWriter, r *http.Request) {
				if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
					sawUpgrade.Store(true)
				}
				if r.Header.Get("X-Middle-Envoy") == "1" {
					sawMiddleHopMarker.Store(true)
				}
				upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
				conn, err := upgrader.Upgrade(w, r, nil)
				if err != nil {
					return
				}
				defer conn.Close()
				for {
					mt, msg, err := conn.ReadMessage()
					if err != nil {
						return
					}
					if err := conn.WriteMessage(mt, msg); err != nil {
						return
					}
				}
			})

			mid := newMiddleEnvoy(up.Addr(), tc.middleAllowsUpgrade)

			// up.Route() pre-appends the upstream's own address to the
			// route's to-list, and PolicyRoute.To appends rather than
			// replaces. Build the route directly so it has a single
			// upstream pointing at the middle Envoy.
			route := &testenv.PolicyRoute{}
			route.From(env.SubdomainURL("ws-mid"))
			route.To(values.Bind(mid.Addr(), func(a string) string { return "http://" + a }))
			route.Policy(func(p *config.Policy) {
				p.AllowPublicUnauthenticatedAccess = true
				p.AllowWebsockets = true
				if tc.pomeriumRemoveHdrs != nil {
					p.RemoveRequestHeaders = tc.pomeriumRemoveHdrs
				}
			})
			env.Add(route)

			env.AddUpstream(up)
			env.AddTask(mid)
			env.Start()
			snippets.WaitStartupComplete(env)

			status, err := dialWS(t, env, route)
			if tc.expectClientSuccess {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				assert.Equal(t, tc.expectClientStatus, status,
					"client-side handshake status mismatch")
			}
			assert.Equal(t, tc.expectBackendUpgrade, sawUpgrade.Load(),
				"backend Upgrade-header observation mismatch")
			assert.Equal(t, tc.expectBackendSawMiddleHop, sawMiddleHopMarker.Load(),
				"backend middle-Envoy marker observation mismatch")
		})
	}
}

// dialWS is a local replacement for upstreams.httpUpstream.DialWS. It
// returns the HTTP status code from the handshake (0 if no response was
// received) so callers can pin the rejection point on negative cases. The
// standard helper dereferences resp unconditionally on error and panics
// for failures that never produced a response (e.g. a TCP-level failure
// between Pomerium's Envoy and the upstream).
func dialWS(t *testing.T, env testenv.Environment, r testenv.Route) (int, error) {
	t.Helper()
	u, err := url.Parse(r.URL().Value())
	if err != nil {
		return 0, err
	}
	u.Scheme = "wss"
	u.Path = "/ws"

	d := &websocket.Dialer{
		HandshakeTimeout: 5 * time.Second,
		TLSClientConfig:  &tls.Config{RootCAs: env.ServerCAs()},
	}
	conn, resp, err := d.DialContext(env.Context(), u.String(), nil)
	status := 0
	if resp != nil {
		status = resp.StatusCode
		if resp.Body != nil {
			_ = resp.Body.Close()
		}
	}
	if err != nil {
		return status, err
	}
	defer conn.Close()
	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if err := conn.WriteMessage(websocket.TextMessage, []byte("hi")); err != nil {
		return status, err
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, msg, err := conn.ReadMessage()
	if err != nil {
		return status, err
	}
	if string(msg) != "hi" {
		return status, fmt.Errorf("got %q want %q", msg, "hi")
	}
	return status, nil
}

// middleEnvoy is a [testenv.Task] that runs an Envoy process listening on a
// loopback port and forwarding to the given upstream. The test controls
// whether the listener and route advertise upgrade_configs: websocket.
type middleEnvoy struct {
	upstream     values.Value[string]
	allowUpgrade bool
	addr         values.MutableValue[string]
}

func newMiddleEnvoy(upstream values.Value[string], allowUpgrade bool) *middleEnvoy {
	return &middleEnvoy{
		upstream:     upstream,
		allowUpgrade: allowUpgrade,
		addr:         values.Deferred[string](),
	}
}

func (m *middleEnvoy) Addr() values.Value[string] { return m.addr }

func (m *middleEnvoy) Run(ctx context.Context) error {
	envoyPath, err := envoy.Extract()
	if err != nil {
		return fmt.Errorf("extract envoy: %w", err)
	}

	upstreamHost, upstreamPort, err := net.SplitHostPort(m.upstream.Value())
	if err != nil {
		return fmt.Errorf("split upstream addr: %w", err)
	}

	ports, err := netutil.AllocatePorts(1)
	if err != nil {
		return fmt.Errorf("allocate port: %w", err)
	}
	listenPort := ports[0]

	// Pomerium's config build blocks on m.addr.Value() via values.Bind. If
	// Run() returns before resolving m.addr, the test wedges instead of
	// failing. Always publish the address on exit; the success path
	// resolves earlier so Pomerium can connect to a live listener.
	var resolveOnce sync.Once
	resolveAddr := func() {
		resolveOnce.Do(func() { m.addr.Resolve("127.0.0.1:" + listenPort) })
	}
	defer resolveAddr()

	dir, err := os.MkdirTemp("", "middle-envoy-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	cfgPath := filepath.Join(dir, "envoy.yaml")
	if err := os.WriteFile(cfgPath, []byte(m.config(listenPort, upstreamHost, upstreamPort)), 0o600); err != nil {
		return err
	}

	logLevel := "warn"
	if v, ok := os.LookupEnv("MIDDLE_ENVOY_LOG_LEVEL"); ok {
		logLevel = v
	}
	cmd := exec.CommandContext(ctx, envoyPath,
		"-c", cfgPath,
		"--log-level", logLevel,
		"--use-dynamic-base-id",
	)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}

	// Reap the subprocess on every Run() exit path. cmd.Wait may only be
	// called once, so guard with sync.Once.
	var waitOnce sync.Once
	var waitErr error
	reap := func() error {
		waitOnce.Do(func() { waitErr = cmd.Wait() })
		return waitErr
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = reap()
	}()

	// Wait until the listener is accepting before publishing the address.
	// The defer above unblocks Pomerium's config build on every exit path;
	// resolving here just makes the success path race-free.
	if err := waitForListen(ctx, "127.0.0.1:"+listenPort, 5*time.Second); err != nil {
		return err
	}
	resolveAddr()

	if err := reap(); err != nil && ctx.Err() == nil {
		return fmt.Errorf("middle envoy exited: %w", err)
	}
	return nil
}

func (m *middleEnvoy) config(listenPort, upstreamHost, upstreamPort string) string {
	upgrade := ""
	if m.allowUpgrade {
		upgrade = "          upgrade_configs:\n          - upgrade_type: websocket\n"
	}
	routeUpgrade := ""
	if m.allowUpgrade {
		routeUpgrade = "                  upgrade_configs:\n                  - upgrade_type: websocket\n"
	}
	accessLog := ""
	if _, ok := os.LookupEnv("MIDDLE_ENVOY_LOG_LEVEL"); ok {
		accessLog = "          access_log:\n" +
			"          - name: envoy.access_loggers.stdout\n" +
			"            typed_config:\n" +
			"              \"@type\": type.googleapis.com/envoy.extensions.access_loggers.stream.v3.StdoutAccessLog\n"
	}
	return fmt.Sprintf(`static_resources:
  listeners:
  - address:
      socket_address: { address: 127.0.0.1, port_value: %s }
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: middle
          codec_type: HTTP1
%s%s          route_config:
            virtual_hosts:
            - name: backend
              domains: ["*"]
              request_headers_to_add:
              - header: { key: X-Middle-Envoy, value: "1" }
              routes:
              - match: { prefix: "/" }
                route:
                  cluster: backend
%s          http_filters:
          - name: envoy.filters.http.router
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
  clusters:
  - name: backend
    type: STATIC
    connect_timeout: 1s
    load_assignment:
      cluster_name: backend
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address: { address: %s, port_value: %s }
`, listenPort, accessLog, upgrade, routeUpgrade, upstreamHost, upstreamPort)
}

func waitForListen(ctx context.Context, addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("middle envoy listener %q not ready after %s", addr, timeout)
}
