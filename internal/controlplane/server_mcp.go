package controlplane

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/grpcutil"
	"github.com/pomerium/pomerium/pkg/mcp/configapi"
)

const (
	mcpConfigAPIDefaultSockName = "pomerium-mcp-configapi.sock"
	mcpConfigAPISocketMode      = 0o600
)

// mcpConfigAPISocketPath returns the path the in-process configapi MCP
// listener binds to. Defaults to a stable name under os.TempDir() when
// the operator did not set internal_mcp.socket_path — mirroring the
// convention for Envoy's admin socket (config/envoyconfig/bootstrap.go).
func (srv *Server) mcpConfigAPISocketPath() string {
	cfg := srv.currentConfig.Load()
	if cfg != nil && cfg.Options != nil && cfg.Options.InternalMCP.SocketPath != "" {
		return cfg.Options.InternalMCP.SocketPath
	}
	return filepath.Join(os.TempDir(), mcpConfigAPIDefaultSockName)
}

// bindMCPConfigAPIListener binds a Unix domain socket for the in-process
// configapi MCP server. Returns nil, nil when internal_mcp.enabled is
// false. Any stale socket file at the target path is removed before
// listening; the socket is chmod'd to 0600 so only same-uid processes
// (pomerium and the Envoy it manages) can connect.
func (srv *Server) bindMCPConfigAPIListener() (net.Listener, error) {
	cfg := srv.currentConfig.Load()
	if cfg == nil || cfg.Options == nil || !cfg.Options.InternalMCP.Enabled {
		return nil, nil
	}
	path := srv.mcpConfigAPISocketPath()
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
	if srv.MCPConfigAPIListener == nil {
		return nil
	}
	return configapi.NewHandler(
		srv.ConnectMux,
		configapi.WithRequestStamp(srv.newSharedKeyStamp()),
	)
}

// newSharedKeyStamp returns a request-stamping function that attaches a
// short-lived shared-key JWT to in-memory Connect requests dispatched
// by the configapi MCP handler. An empty or unloadable shared key is a
// gross misconfiguration: the stamp fails the dispatch so the MCP
// client gets a structured error, rather than the downstream rejecting
// an unauthenticated request with a generic auth failure the operator
// cannot diagnose.
func (srv *Server) newSharedKeyStamp() configapi.RequestStamp {
	return func(req *http.Request) error {
		cfg := srv.currentConfig.Load()
		if cfg == nil || cfg.Options == nil {
			return errors.New("mcp: no controlplane config loaded; cannot sign in-process Connect request")
		}
		key, err := cfg.Options.GetSharedKey()
		if err != nil {
			log.Ctx(req.Context()).Error().Err(err).
				Msg("mcp: resolve shared key for in-process Connect call")
			return fmt.Errorf("mcp: resolve shared key: %w", err)
		}
		if len(key) == 0 {
			return errors.New("mcp: shared key is empty; configure shared_secret to use the in-process MCP server")
		}
		rawjwt, err := grpcutil.SignSharedKey(key)
		if err != nil {
			return fmt.Errorf("mcp: sign shared-key JWT: %w", err)
		}
		req.Header.Set("Authorization", "Bearer Pomerium-"+rawjwt)
		return nil
	}
}
