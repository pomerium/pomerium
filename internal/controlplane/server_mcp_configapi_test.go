package controlplane_test

import (
	"context"
	"net"
	"os"
	"path/filepath"
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

// TestServer_MCPConfigAPI exercises the startup-bound Unix domain socket
// for the in-process configapi MCP server. The listener is bound once
// when InternalMCP.Enabled is true; there is no runtime reconfiguration,
// so the test surface is simply "is the socket there with the right
// permissions and accepting connections, or absent."
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

	runServer := func(t *testing.T, cfg *config.Config) {
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
	}

	t.Run("disabled by default", func(t *testing.T) {
		t.Parallel()

		ports, err := netutil.AllocatePorts(5)
		require.NoError(t, err)

		sockPath := filepath.Join(t.TempDir(), "configapi.sock")
		cfg := newConfig(ports)
		// InternalMCP.Enabled stays false; SocketPath is set only to
		// assert the file is NOT created at it.
		cfg.Options.InternalMCP.SocketPath = sockPath

		runServer(t, cfg)

		// Bind decision is synchronous in NewServer, so by the time
		// runServer returns the answer is committed — no need to poll.
		_, statErr := os.Stat(sockPath)
		require.True(t, os.IsNotExist(statErr),
			"%s must not be created when internal_mcp.enabled is false (stat err: %v)", sockPath, statErr)
	})

	t.Run("binds at startup when enabled", func(t *testing.T) {
		t.Parallel()

		ports, err := netutil.AllocatePorts(5)
		require.NoError(t, err)

		sockPath := filepath.Join(t.TempDir(), "configapi.sock")
		cfg := newConfig(ports)
		cfg.Options.InternalMCP.Enabled = true
		cfg.Options.InternalMCP.SocketPath = sockPath

		runServer(t, cfg)

		require.Eventually(t, func() bool {
			info, statErr := os.Stat(sockPath)
			if statErr != nil {
				return false
			}
			return info.Mode().Perm() == 0o600
		}, 3*time.Second, 50*time.Millisecond,
			"%s must exist with mode 0600 after startup", sockPath)

		conn, err := net.DialTimeout("unix", sockPath, time.Second)
		require.NoError(t, err, "unix socket should accept connections")
		_ = conn.Close()
	})

	t.Run("removes stale socket file before bind", func(t *testing.T) {
		t.Parallel()

		ports, err := netutil.AllocatePorts(5)
		require.NoError(t, err)

		sockPath := filepath.Join(t.TempDir(), "configapi.sock")
		require.NoError(t, os.WriteFile(sockPath, []byte("stale"), 0o644),
			"seed a stale file at the socket path")

		cfg := newConfig(ports)
		cfg.Options.InternalMCP.Enabled = true
		cfg.Options.InternalMCP.SocketPath = sockPath

		runServer(t, cfg)

		conn, err := net.DialTimeout("unix", sockPath, time.Second)
		require.NoError(t, err, "stale file should have been removed and replaced with a working socket")
		_ = conn.Close()

		info, err := os.Stat(sockPath)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o600), info.Mode().Perm(),
			"chmod should have been applied even after replacing a stale file")
	})
}
