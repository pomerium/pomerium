package controlplane

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/config/envoyconfig/filemgr"
	"github.com/pomerium/pomerium/internal/events"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/netutil"
)

// TestServer_ExtProcHandlerAlwaysInstalled guards the Zero config-sync invariant:
// the MCP ext_proc handler is installed at controlplane startup regardless of
// RuntimeFlagMCP. With the handler always present, the unconditional
// OnConfigChange(cfg) in update() picks up MCP routes that arrive after startup.
func TestServer_ExtProcHandlerAlwaysInstalled(t *testing.T) {
	t.Parallel()

	ports, err := netutil.AllocatePorts(5)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	startup := newTestConfig(ports)
	startup.Options.RuntimeFlags = config.RuntimeFlags{config.RuntimeFlagMCP: false}

	src := config.NewStaticSource(startup)
	srv, err := NewServer(ctx, startup, config.NewMetricsManager(ctx, src), events.New(),
		filemgr.NewManager(filemgr.WithCacheDir(t.TempDir())))
	require.NoError(t, err)

	require.NotNil(t, srv.mcpExtProcHandler,
		"MCP ext_proc handler must be installed at startup even with MCP off")

	enabled := startup.Clone()
	enabled.Options.RuntimeFlags = config.RuntimeFlags{config.RuntimeFlagMCP: true}
	handlerBefore := srv.mcpExtProcHandler
	require.NoError(t, srv.update(ctx, enabled))
	require.Same(t, handlerBefore, srv.mcpExtProcHandler,
		"handler must not be re-installed when MCP flips on — the at-startup handler is the one")
}

func newTestConfig(ports []string) *config.Config {
	cfg := &config.Config{
		GRPCPort:     ports[0],
		HTTPPort:     ports[1],
		OutboundPort: ports[2],
		MetricsPort:  ports[3],
		DebugPort:    ports[4],

		Options: config.NewDefaultOptions(),
	}
	cfg.Options.AuthenticateURLString = "https://authenticate.localhost.pomerium.io"
	cfg.Options.SharedKey = cryptutil.NewBase64Key()
	return cfg
}
