package controlplane_test

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
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
// when NewServer runs, on a path provided via WithMCPConfigAPISocketPath
// in tests (production uses os.TempDir() + a fixed name).
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

	// shortTempDir returns a temp dir under /tmp rather than t.TempDir()
	// (which on macOS nests under /var/folders/... and can push the socket
	// path past the 104-byte sun_path limit).
	shortTempDir := func(t *testing.T) string {
		t.Helper()
		dir, err := os.MkdirTemp("/tmp", "pmtest-")
		require.NoError(t, err)
		t.Cleanup(func() { _ = os.RemoveAll(dir) })
		return dir
	}

	runServer := func(t *testing.T, cfg *config.Config, sockPath string) {
		t.Helper()
		ctx, cancel := context.WithCancel(t.Context())
		t.Cleanup(cancel)

		src := config.NewStaticSource(cfg)
		srv, err := controlplane.NewServer(ctx, cfg, config.NewMetricsManager(ctx, src), events.New(),
			filemgr.NewManager(filemgr.WithCacheDir(t.TempDir())),
			controlplane.WithMCPConfigAPISocketPath(sockPath))
		require.NoError(t, err)

		done := make(chan error, 1)
		go func() { done <- srv.Run(ctx) }()
		t.Cleanup(func() {
			cancel()
			<-done
		})
	}

	t.Run("binds at startup", func(t *testing.T) {
		t.Parallel()

		ports, err := netutil.AllocatePorts(5)
		require.NoError(t, err)

		sockPath := filepath.Join(shortTempDir(t), "s")
		runServer(t, newConfig(ports), sockPath)

		info, err := os.Stat(sockPath)
		require.NoError(t, err, "%s must exist after startup", sockPath)
		require.Equal(t, os.FileMode(0o600), info.Mode().Perm(),
			"%s must be chmod'd to 0o600", sockPath)

		conn, err := net.DialTimeout("unix", sockPath, time.Second)
		require.NoError(t, err, "unix socket should accept connections")
		_ = conn.Close()
	})

	t.Run("path over sun_path limit is rejected with a clear message", func(t *testing.T) {
		t.Parallel()

		ports, err := netutil.AllocatePorts(5)
		require.NoError(t, err)

		// 200-char absolute path — well over the 104-byte sun_path limit.
		sockPath := "/tmp/" + strings.Repeat("a", 200)
		runServer(t, newConfig(ports), sockPath)

		// The bind failure is non-fatal; the listener is disabled and no
		// socket file is created.
		_, statErr := os.Stat(sockPath)
		require.True(t, os.IsNotExist(statErr),
			"%s must not be created when bind fails (stat err: %v)", sockPath, statErr)
	})

	t.Run("removes stale socket file before bind", func(t *testing.T) {
		t.Parallel()

		ports, err := netutil.AllocatePorts(5)
		require.NoError(t, err)

		sockPath := filepath.Join(shortTempDir(t), "s")
		require.NoError(t, os.WriteFile(sockPath, []byte("stale"), 0o644),
			"seed a stale file at the socket path")

		runServer(t, newConfig(ports), sockPath)

		conn, err := net.DialTimeout("unix", sockPath, time.Second)
		require.NoError(t, err, "stale file should have been removed and replaced with a working socket")
		_ = conn.Close()

		info, err := os.Stat(sockPath)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o600), info.Mode().Perm(),
			"chmod should have been applied even after replacing a stale file")
	})
}
