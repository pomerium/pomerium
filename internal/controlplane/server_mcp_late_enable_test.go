package controlplane

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/config/envoyconfig/filemgr"
	"github.com/pomerium/pomerium/internal/events"
	"github.com/pomerium/pomerium/pkg/netutil"
)

// TestServer_MCPEnabledAfterStartup_InstallsExtProcHandler is the RED test for
// review finding C1.
//
// Before C1, if RuntimeFlagMCP was off at NewServer time, srv.mcpExtProcHandler
// stayed nil forever: the ext_proc server was registered with a nil handler
// and update() only emitted a "handler remains nil until restart" warning when
// the flag later flipped on. In the Pomerium Zero flow — where the flag can
// arrive via databroker-delivered config — this meant MCP routes silently
// lost upstream token injection.
//
// The fix: register the ext_proc server unconditionally with an atomic.Pointer
// handler slot, and install the handler on the fly inside update() when the
// flag flips on.
func TestServer_MCPEnabledAfterStartup_InstallsExtProcHandler(t *testing.T) {
	t.Parallel()

	ports, err := netutil.AllocatePorts(5)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	startup := newTestConfig(t, ports)
	// Startup with MCP flag OFF (simulates a Zero-managed deployment where
	// the flag + MCP routes arrive later via config sync).
	startup.Options.RuntimeFlags = config.RuntimeFlags{config.RuntimeFlagMCP: false}

	src := config.NewStaticSource(startup)
	srv, err := NewServer(ctx, startup, config.NewMetricsManager(ctx, src), events.New(),
		filemgr.NewManager(filemgr.WithCacheDir(t.TempDir())))
	require.NoError(t, err)

	require.NotNil(t, srv.extProcServer,
		"ext_proc server must be registered even when MCP is disabled at startup")
	assert.Nil(t, srv.mcpExtProcHandler,
		"no handler should exist yet — MCP is off")

	// Deliver a config with MCP enabled (as Zero would via databroker config sync).
	enabled := startup.Clone()
	enabled.Options.RuntimeFlags = config.RuntimeFlags{config.RuntimeFlagMCP: true}
	require.NoError(t, srv.update(ctx, enabled))

	require.NotNil(t, srv.mcpExtProcHandler,
		"ext_proc MCP handler must be installed after enabling MCP at runtime; "+
			"pre-fix behavior left this nil and only logged a warning")
	// Separately, extproc_test.go:TestNewServer asserts that SetHandler
	// exposes the handler to incoming Process() calls via currentHandler().
}

func newTestConfig(_ *testing.T, ports []string) *config.Config {
	cfg := &config.Config{
		GRPCPort:     ports[0],
		HTTPPort:     ports[1],
		OutboundPort: ports[2],
		MetricsPort:  ports[3],
		DebugPort:    ports[4],

		Options: config.NewDefaultOptions(),
	}
	cfg.Options.AuthenticateURLString = "https://authenticate.localhost.pomerium.io"
	cfg.Options.SigningKey = "LS0tLS1CRUdJTiBFQyBQUklWQVRFIEtFWS0tLS0tCk1IY0NBUUVFSUpCMFZkbko1VjEvbVlpYUlIWHhnd2Q0Yzd5YWRTeXMxb3Y0bzA1b0F3ekdvQW9HQ0NxR1NNNDkKQXdFSG9VUURRZ0FFVUc1eENQMEpUVDFINklvbDhqS3VUSVBWTE0wNENnVzlQbEV5cE5SbVdsb29LRVhSOUhUMwpPYnp6aktZaWN6YjArMUt3VjJmTVRFMTh1dy82MXJVQ0JBPT0KLS0tLS1FTkQgRUMgUFJJVkFURSBLRVktLS0tLQo="
	cfg.Options.SharedKey = "JDNjY2ITDlARvNaQXjc2Djk+GA6xeCy4KiozmZfdbTs="
	return cfg
}
