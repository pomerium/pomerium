package controlplane

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/config/envoyconfig/filemgr"
	"github.com/pomerium/pomerium/internal/events"
	"github.com/pomerium/pomerium/pkg/netutil"
)

// runServer starts a fresh controlplane.Server in a goroutine and returns it.
// The server is torn down automatically when the test ends.
func runServer(t *testing.T, cfg *config.Config) (*Server, context.Context) {
	t.Helper()

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	src := config.NewStaticSource(cfg)
	srv, err := NewServer(ctx, cfg, config.NewMetricsManager(ctx, src), events.New(),
		filemgr.NewManager(filemgr.WithCacheDir(t.TempDir())))
	require.NoError(t, err)

	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return srv, ctx
}

// dialable returns true if addr accepts a TCP connection within timeout.
func dialable(addr string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func TestServer_MCPConfigAPI_DisabledByDefault(t *testing.T) {
	t.Parallel()

	ports, err := netutil.AllocatePorts(6)
	require.NoError(t, err)

	cfg := newTestConfig(ports[:5])
	// ports[5] is an extra, candidate address MCP would bind to if enabled.
	mcpAddr := net.JoinHostPort("127.0.0.1", ports[5])

	runServer(t, cfg)
	// Any attempt to dial times out (or refuses) — no listener was bound.
	require.Never(t, func() bool { return dialable(mcpAddr, 50*time.Millisecond) },
		300*time.Millisecond, 50*time.Millisecond, "%s must not be bound", mcpAddr)
}

func TestServer_MCPConfigAPI_StartsOnConfigChange(t *testing.T) {
	t.Parallel()

	ports, err := netutil.AllocatePorts(6)
	require.NoError(t, err)

	cfg := newTestConfig(ports[:5])
	mcpAddr := net.JoinHostPort("127.0.0.1", ports[5])

	srv, ctx := runServer(t, cfg)

	// Baseline: not bound.
	require.False(t, dialable(mcpAddr, 100*time.Millisecond))

	updated := cfg.Clone()
	updated.Options.MCPAddress = mcpAddr
	require.NoError(t, srv.OnConfigChange(ctx, updated))

	require.Eventually(t, func() bool { return dialable(mcpAddr, 50*time.Millisecond) },
		3*time.Second, 50*time.Millisecond, "mcp listener should become reachable at %s", mcpAddr)
}

func TestServer_MCPConfigAPI_StopsOnConfigChange(t *testing.T) {
	t.Parallel()

	ports, err := netutil.AllocatePorts(6)
	require.NoError(t, err)

	cfg := newTestConfig(ports[:5])
	mcpAddr := net.JoinHostPort("127.0.0.1", ports[5])
	cfg.Options.MCPAddress = mcpAddr

	srv, ctx := runServer(t, cfg)

	require.Eventually(t, func() bool { return dialable(mcpAddr, 50*time.Millisecond) },
		3*time.Second, 50*time.Millisecond, "mcp listener should be reachable at %s", mcpAddr)

	cleared := cfg.Clone()
	cleared.Options.MCPAddress = ""
	require.NoError(t, srv.OnConfigChange(ctx, cleared))

	require.Eventually(t, func() bool { return !dialable(mcpAddr, 50*time.Millisecond) },
		3*time.Second, 50*time.Millisecond, "mcp listener should stop accepting connections")
}

func TestServer_MCPConfigAPI_RebindOnAddressChange(t *testing.T) {
	t.Parallel()

	ports, err := netutil.AllocatePorts(7)
	require.NoError(t, err)

	cfg := newTestConfig(ports[:5])
	addr1 := net.JoinHostPort("127.0.0.1", ports[5])
	addr2 := net.JoinHostPort("127.0.0.1", ports[6])
	cfg.Options.MCPAddress = addr1

	srv, ctx := runServer(t, cfg)

	require.Eventually(t, func() bool { return dialable(addr1, 50*time.Millisecond) },
		3*time.Second, 50*time.Millisecond)

	updated := cfg.Clone()
	updated.Options.MCPAddress = addr2
	require.NoError(t, srv.OnConfigChange(ctx, updated))

	require.Eventually(t, func() bool {
		return dialable(addr2, 50*time.Millisecond) && !dialable(addr1, 50*time.Millisecond)
	}, 3*time.Second, 50*time.Millisecond, "listener should rebind from %s to %s", addr1, addr2)
}
