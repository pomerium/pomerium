package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/pomerium/pomerium/internal/log"
	oauth21proto "github.com/pomerium/pomerium/internal/oauth21/gen"
	"github.com/pomerium/pomerium/pkg/telemetry/requestid"
)

// ListMCPServers returns a list of MCP servers that are registered,
// and whether the current user has access to them.
func (srv *Handler) ListRoutes(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	log.Ctx(ctx).Debug().
		Str("method", r.Method).
		Str("host", r.Host).
		Str("path", r.URL.Path).
		Msg("mcp/list-routes: request received")

	if r.Method != http.MethodGet {
		log.Ctx(ctx).Debug().Str("method", r.Method).Msg("mcp/list-routes: rejecting non-GET method")
		http.Error(w, "invalid method", http.StatusMethodNotAllowed)
		return
	}

	err := srv.listMCPServers(w, r)
	if err != nil {
		reqID := requestid.FromContext(ctx)
		log.Ctx(ctx).Error().Err(err).Str("request-id", reqID).Msg("mcp/list-routes: failed to list MCP servers")
		http.Error(w,
			fmt.Sprintf("Internal error. Check logs for request ID: %s", reqID),
			http.StatusInternalServerError)
		return
	}
}

func (srv *Handler) listMCPServers(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()

	claims, err := getClaimsFromRequest(r)
	if err != nil {
		return fmt.Errorf("failed to get claims from request: %w", err)
	}

	log.Ctx(ctx).Debug().
		Interface("claims", claims).
		Msg("mcp/list-routes: extracted JWT claims")

	userID, ok := getUserIDFromClaims(claims)
	if !ok {
		return fmt.Errorf("user id is not present in claims")
	}

	log.Ctx(ctx).Debug().
		Str("user-id", userID).
		Msg("mcp/list-routes: listing servers for user")

	return srv.listMCPServersForUser(ctx, w, userID, nil)
}

// allServerInfos returns a serverInfo slice for every configured MCP server host.
func (srv *Handler) allServerInfos() []serverInfo {
	var servers []serverInfo
	for v := range srv.hosts.All() {
		servers = append(servers, serverInfo{
			Name:        v.Name,
			Description: v.Description,
			LogoURL:     v.LogoURL,
			URL:         v.URL,
			NeedsOauth:  true,
			host:        v.Host,
			routeID:     v.RouteID,
			upstreamURL: v.UpstreamURL,
		})
	}
	return servers
}

// listMCPServersForUser writes the routes listing response for a user, optionally
// including a per-route error map keyed by the route URL as the client sent it.
func (srv *Handler) listMCPServersForUser(
	ctx context.Context,
	w http.ResponseWriter,
	userID string,
	routeErrors map[string]string,
) error {
	servers := srv.allServerInfos()

	log.Ctx(ctx).Debug().
		Str("user-id", userID).
		Int("server-count", len(servers)).
		Msg("mcp/list-routes: checking connection status for servers")

	servers, err := srv.checkHostsConnectedForUser(ctx, userID, servers)
	if err != nil {
		return fmt.Errorf("failed to check hosts connected for user %s: %w", userID, err)
	}

	connectedCount := 0
	for _, s := range servers {
		if s.Connected {
			connectedCount++
		}
	}

	log.Ctx(ctx).Debug().
		Str("user-id", userID).
		Int("total-servers", len(servers)).
		Int("connected-servers", connectedCount).
		Msg("mcp/list-routes: connection status checked")

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	w.WriteHeader(http.StatusOK)

	type response struct {
		Servers []serverInfo      `json:"servers"`
		Errors  map[string]string `json:"errors,omitempty"`
	}

	log.Ctx(ctx).Debug().
		Str("user-id", userID).
		Int("server-count", len(servers)).
		Int("error-count", len(routeErrors)).
		Msg("mcp/list-routes: sending response")

	return json.NewEncoder(w).Encode(response{
		Servers: servers,
		Errors:  routeErrors,
	})
}

// UpstreamTokenStatus is the user-visible state of a stored upstream MCP token.
// It is embedded in both the routes listing JSON and PortalRouteInfo so the fields
// are declared and mapped once.
type UpstreamTokenStatus struct {
	// TokenExpiresAt is the stored upstream access token expiry in RFC 3339 format,
	// empty if there is no token or the token has no known expiry.
	TokenExpiresAt string `json:"token_expires_at,omitempty"`
	// RefreshTokenAvailable indicates whether the stored token carries a refresh token.
	RefreshTokenAvailable bool `json:"refresh_token_available"`
}

// newUpstreamTokenStatus derives the user-visible status from a stored upstream token.
// A nil token yields the zero status.
func newUpstreamTokenStatus(token *oauth21proto.UpstreamMCPToken) UpstreamTokenStatus {
	var s UpstreamTokenStatus
	if t := token.GetExpiresAt(); t != nil {
		s.TokenExpiresAt = t.AsTime().Format(time.RFC3339)
	}
	s.RefreshTokenAvailable = token.GetRefreshToken() != ""
	return s
}

func (srv *Handler) checkHostsConnectedForUser(
	ctx context.Context,
	userID string,
	servers []serverInfo,
) ([]serverInfo, error) {
	eg, ctx := errgroup.WithContext(ctx)
	for i := range servers {
		if !servers[i].NeedsOauth {
			servers[i].Connected = true
			continue
		}
		eg.Go(func() error {
			if servers[i].routeID != "" && servers[i].upstreamURL != "" {
				token, err := srv.storage.GetUpstreamMCPToken(ctx, userID, servers[i].routeID, servers[i].upstreamURL)
				if err != nil && !isNotFound(err) {
					return fmt.Errorf("failed to get upstream MCP token for user %s: %w", userID, err)
				}
				servers[i].Connected = err == nil && token != nil
				servers[i].UpstreamTokenStatus = newUpstreamTokenStatus(token)
			}
			return nil
		})
	}

	err := eg.Wait()
	if err != nil {
		return nil, fmt.Errorf("failed to check hosts connected for user %s: %w", userID, err)
	}
	return servers, nil
}

type serverInfo struct {
	Name                string `json:"name,omitempty"`
	Description         string `json:"description,omitempty"`
	LogoURL             string `json:"logo_url,omitempty"`
	URL                 string `json:"url"`
	Connected           bool   `json:"connected"`
	NeedsOauth          bool   `json:"needs_oauth"`
	UpstreamTokenStatus        // embedded: encoding/json flattens its fields into this object
	host                string `json:"-"`
	routeID             string `json:"-"`
	upstreamURL         string `json:"-"`
}
