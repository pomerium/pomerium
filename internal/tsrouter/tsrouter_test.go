package tsrouter_test

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/net/netns"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"tailscale.com/tstest/integration"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/logger"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/databroker"
	"github.com/pomerium/pomerium/internal/tsrouter"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/nullable"
)

func TestTSRouter(t *testing.T) {
	controlURL := startControl(t)
	outboundPort := startDatabroker(t)

	// stands in for Pomerium. In raw TCP mode (terminate_tls unset) the router
	// passes the TCP stream through, so Pomerium terminates TLS.
	pomerium := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "hello from pomerium")
	}))
	t.Cleanup(pomerium.Close)

	cfg := &config.Config{
		Options:      config.NewDefaultOptions(),
		OutboundPort: outboundPort,
	}
	cfg.Options.Addr = pomerium.Listener.Addr().String()
	cfg.Options.SharedKey = cryptutil.NewBase64Key()
	cfg.Options.RuntimeFlags = config.RuntimeFlags{config.RuntimeFlagTailscale: true}
	cfg.Options.TailscaleListeners = nullable.From([]config.TailscaleListenerSettings{{
		Hostname:   nullable.From("pomerium-test"),
		ControlURL: nullable.From(controlURL),
		Ephemeral:  nullable.From(true),
		ListenAddr: nullable.From(":443"),
	}})

	router := tsrouter.New(noop.NewTracerProvider(), tsrouter.WithDirectory(t.TempDir()))
	go router.Run(t.Context())
	router.OnConfigChange(cfg)

	client := &tsnet.Server{
		Dir:        t.TempDir(),
		ControlURL: controlURL,
		Hostname:   "client",
		Store:      new(mem.Store),
		Ephemeral:  true,
	}
	t.Cleanup(func() { _ = client.Close() })
	_, err := client.Up(t.Context())
	require.NoError(t, err)

	waitForHomeDERPConnected(t, client)

	lc, err := client.LocalClient()
	require.NoError(t, err)

	// wait for the router's node to join the tailnet
	var routerIP netip.Addr
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		st, err := lc.Status(t.Context())
		require.NoError(c, err)
		for _, peer := range st.Peer {
			// wait for the router to report a home DERP region as well, so the
			// first WireGuard handshake isn't dropped and retried after 5s
			if peer.HostName == "pomerium-test" && len(peer.TailscaleIPs) > 0 && peer.Relay != "" {
				routerIP = peer.TailscaleIPs[0]
				return
			}
		}
		assert.Fail(c, "router node not found in tailnet peers")
	}, 30*time.Second, 100*time.Millisecond)

	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext:     client.Dial,
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		// the first attempt can be dropped while the nodes finish their DERP
		// handshake, so keep attempts short and let EventuallyWithT retry
		Timeout: time.Second,
	}
	u := "https://" + net.JoinHostPort(routerIP.String(), "443") + "/"

	// the listener only starts once the router holds the databroker lease,
	// and the first packets may race the DERP handshake, so retry
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		res, err := httpClient.Get(u)
		require.NoError(c, err)
		defer res.Body.Close()
		body, err := io.ReadAll(res.Body)
		require.NoError(c, err)
		assert.Equal(c, http.StatusOK, res.StatusCode)
		assert.Equal(c, "hello from pomerium", string(body))
	}, 30*time.Second, 250*time.Millisecond)
}

// startControl runs an in-process tailscale control server with its own DERP
// and STUN servers, mirroring tsnet's own tests.
func startControl(t *testing.T) string {
	t.Helper()

	// tsnet binds its sockets to the default network interface, which can't
	// reach the STUN server on 127.0.0.1. Netcheck then reports UDP as
	// blocked only after its 3s timeout. (tailscale corp#4520)
	netns.SetEnabled(false)
	t.Cleanup(func() { netns.SetEnabled(true) })

	control := &testcontrol.Server{
		DERPMap: integration.RunDERPAndSTUN(t, logger.Discard, "127.0.0.1"),
		DNSConfig: &tailcfg.DNSConfig{
			Proxied: true,
		},
		MagicDNSDomain: "tail-scale.ts.net",
		Logf:           logger.Discard,
	}
	control.HTTPTestServer = httptest.NewUnstartedServer(control)
	control.HTTPTestServer.Start()
	t.Cleanup(control.HTTPTestServer.Close)
	return control.HTTPTestServer.URL
}

// startDatabroker serves an in-memory databroker on a local port, which the
// router reaches as if it were the outbound gRPC port.
func startDatabroker(t *testing.T) string {
	t.Helper()

	backend := databroker.NewBackendServer(noop.NewTracerProvider())
	t.Cleanup(backend.Stop)

	li, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	srv := grpc.NewServer()
	databrokerpb.RegisterDataBrokerServiceServer(srv, backend)
	go func() { _ = srv.Serve(li) }()
	t.Cleanup(srv.Stop)

	return strconv.Itoa(li.Addr().(*net.TCPAddr).Port)
}

// waitForHomeDERPConnected waits until s has picked a home DERP region and
// received a frame from it. Until then, DERP drops packets sent to s, so the
// first WireGuard handshake would be lost and only retried after 5s. This
// mirrors the helper in tsnet's own tests.
func waitForHomeDERPConnected(t *testing.T, s *tsnet.Server) {
	t.Helper()

	health := s.Sys().HealthTracker.Get()
	magicSock := s.Sys().MagicSock.Get()
	require.Eventually(t, func() bool {
		r := magicSock.GetLastNetcheckReport(t.Context())
		return r != nil && r.PreferredDERP != 0 &&
			!health.GetDERPRegionReceivedTime(r.PreferredDERP).IsZero()
	}, 30*time.Second, 20*time.Millisecond)
}
