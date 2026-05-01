package controlplane_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/config/envoyconfig/filemgr"
	"github.com/pomerium/pomerium/internal/controlplane"
	"github.com/pomerium/pomerium/internal/events"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/netutil"
)

// TestServer_MCPConfigAPI exercises the MCP ConfigService listener supervisor
// across its four lifecycle states: disabled (no MCPAddress), starting on a
// config change, stopping on a config change, and rebinding when the address
// changes. Helpers are declared inline so the file's package-test surface is
// just this one function — keeps fixture sprawl out of the controlplane_test
// namespace.
func TestServer_MCPConfigAPI(t *testing.T) {
	t.Parallel()

	newConfig := func(ports []string) *config.Config {
		cfg := &config.Config{
			GRPCPort:     ports[0],
			HTTPPort:     ports[1],
			OutboundPort: ports[2],
			MetricsPort:  ports[3],
			DebugPort:    ports[4],
			Options:      config.NewDefaultOptions(),
		}
		cfg.Options.AuthenticateURLString = "https://authenticate.localhost.pomerium.io"
		cfg.Options.SharedKey = cryptutil.NewBase64Key()
		return cfg
	}

	runServer := func(t *testing.T, cfg *config.Config) (*controlplane.Server, context.Context) {
		t.Helper()
		ctx, cancel := context.WithCancel(t.Context())
		t.Cleanup(cancel)

		src := config.NewStaticSource(cfg)
		srv, err := controlplane.NewServer(ctx, cfg, config.NewMetricsManager(ctx, src), events.New(),
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

	dialable := func(addr string, timeout time.Duration) bool {
		conn, err := net.DialTimeout("tcp", addr, timeout)
		if err != nil {
			return false
		}
		_ = conn.Close()
		return true
	}

	t.Run("disabled by default", func(t *testing.T) {
		t.Parallel()

		ports, err := netutil.AllocatePorts(6)
		require.NoError(t, err)

		cfg := newConfig(ports[:5])
		mcpAddr := net.JoinHostPort("127.0.0.1", ports[5])

		runServer(t, cfg)
		require.Never(t, func() bool { return dialable(mcpAddr, 50*time.Millisecond) },
			300*time.Millisecond, 50*time.Millisecond, "%s must not be bound", mcpAddr)
	})

	t.Run("starts on config change", func(t *testing.T) {
		t.Parallel()

		ports, err := netutil.AllocatePorts(6)
		require.NoError(t, err)

		cfg := newConfig(ports[:5])
		mcpAddr := net.JoinHostPort("127.0.0.1", ports[5])

		srv, ctx := runServer(t, cfg)
		require.False(t, dialable(mcpAddr, 100*time.Millisecond))

		updated := cfg.Clone()
		updated.Options.MCPAddress = mcpAddr
		require.NoError(t, srv.OnConfigChange(ctx, updated))

		require.Eventually(t, func() bool { return dialable(mcpAddr, 50*time.Millisecond) },
			3*time.Second, 50*time.Millisecond, "mcp listener should become reachable at %s", mcpAddr)
	})

	t.Run("stops on config change", func(t *testing.T) {
		t.Parallel()

		ports, err := netutil.AllocatePorts(6)
		require.NoError(t, err)

		cfg := newConfig(ports[:5])
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
	})

	t.Run("rebinds on address change", func(t *testing.T) {
		t.Parallel()

		ports, err := netutil.AllocatePorts(7)
		require.NoError(t, err)

		cfg := newConfig(ports[:5])
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
	})
}
