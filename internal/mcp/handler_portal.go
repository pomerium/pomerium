package mcp

import (
	"context"
	"fmt"

	"github.com/pomerium/pomerium/internal/log"
)

// PortalRouteInfo contains MCP connection info needed by the routes portal.
type PortalRouteInfo struct {
	Host      string
	ServerURL string
	Connected bool
}

// GetPortalInfoForUser returns MCP connection status for all server routes,
// for use by the routes portal. It returns nil if no MCP hosts are configured.
func (srv *Handler) GetPortalInfoForUser(ctx context.Context, userID string) ([]PortalRouteInfo, error) {
	servers := srv.allServerInfos()
	if len(servers) == 0 {
		return nil, nil
	}

	servers, err := srv.checkHostsConnectedForUser(ctx, userID, servers)
	if err != nil {
		return nil, fmt.Errorf("check hosts connected for user %s: %w", userID, err)
	}

	result := make([]PortalRouteInfo, len(servers))
	for i, s := range servers {
		result[i] = PortalRouteInfo{
			Host:      s.host,
			ServerURL: s.URL,
			Connected: s.Connected,
		}
	}

	log.Ctx(ctx).Debug().
		Str("user-id", userID).
		Int("server-count", len(result)).
		Msg("mcp/portal: computed portal route info")

	return result, nil
}
