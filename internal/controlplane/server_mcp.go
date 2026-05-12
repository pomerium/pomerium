package controlplane

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"

	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/pkg/grpcutil"
	"github.com/pomerium/pomerium/pkg/mcp/configapi"
)

const (
	// Mirrors the convention used for the Envoy admin socket in
	// config/envoyconfig/bootstrap.go.
	mcpConfigAPIDefaultSockName = "pomerium-mcp"
	mcpConfigAPISocketMode      = 0o600

	// sun_path is 108 bytes on Linux, 104 on macOS/BSD. Use the smaller
	// limit so a borderline-long path fails identically across platforms.
	maxUnixSocketPathLen = 104
)

// bindMCPConfigAPIListener binds a Unix domain socket for the in-process
// configapi MCP server, removing any stale file at the path and forcing
// 0o600 permissions so only same-uid processes can connect. The socket
// is always bound at startup; operators opt in or out by writing a
// route that targets it.
func (srv *Server) bindMCPConfigAPIListener() (net.Listener, error) {
	path := srv.options.mcpConfigAPISocketPath
	if path == "" {
		path = filepath.Join(os.TempDir(), mcpConfigAPIDefaultSockName)
	}
	if len(path) > maxUnixSocketPathLen {
		return nil, fmt.Errorf(
			"mcp: socket path %q is %d bytes, over the kernel sun_path limit (%d); "+
				"$TMPDIR may be unusually long (e.g. systemd PrivateTmp) — set TMPDIR=/tmp or shorten the working directory",
			path, len(path), maxUnixSocketPathLen)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("mcp: remove stale socket %q: %w", path, err)
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("mcp: bind unix socket %q: %w", path, err)
	}
	if err := os.Chmod(path, mcpConfigAPISocketMode); err != nil {
		_ = l.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("mcp: chmod %q: %w", path, err)
	}
	return l, nil
}

// mcpConfigAPIHandler returns the MCP Streamable HTTP handler that
// fronts the in-process ConfigService. The downstream
// securedServer.authorize (internal/databroker/server_secured.go)
// requires a shared-key bearer on every method, so every tool dispatch
// must stamp one via newSharedKeyStamp.
//
// Returns nil when the listener is not bound.
func (srv *Server) mcpConfigAPIHandler() http.Handler {
	if srv.mcpConfigAPIListener == nil {
		return nil
	}
	return configapi.NewHandler(
		srv.ConnectMux,
		configapi.WithRequestStamp(srv.newSharedKeyStamp()),
	)
}

// newSharedKeyStamp returns a request-stamping function that attaches a
// short-lived shared-key JWT to in-memory Connect requests. Failure
// returns a structured error so the MCP client sees a diagnosable
// "missing/empty shared key" rather than a downstream generic auth
// rejection.
func (srv *Server) newSharedKeyStamp() configapi.RequestStamp {
	return func(req *http.Request) error {
		cfg := srv.currentConfig.Load()
		if cfg == nil || cfg.Options == nil {
			return errors.New("mcp: no controlplane config loaded; cannot sign in-process Connect request")
		}
		key, err := cfg.Options.GetSharedKey()
		if err != nil {
			return fmt.Errorf("mcp: resolve shared key: %w", err)
		}
		if len(key) == 0 {
			return errors.New("mcp: shared key is empty; configure shared_secret to use the in-process MCP server")
		}
		rawjwt, err := grpcutil.SignSharedKey(key)
		if err != nil {
			return fmt.Errorf("mcp: sign shared-key JWT: %w", err)
		}
		req.Header.Set(httputil.HeaderAuthorization, "Bearer "+httputil.AuthorizationTypePomerium+"-"+rawjwt)
		return nil
	}
}
