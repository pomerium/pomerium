package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/pomerium/pomerium/internal/log"
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
		log.Ctx(ctx).Error().Err(err).Msg("mcp/list-routes: failed to list MCP servers")
		http.Error(w, err.Error(), http.StatusInternalServerError)
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

	return srv.listMCPServersForUser(ctx, w, userID)
}

func (srv *Handler) listMCPServersForUser(ctx context.Context, w http.ResponseWriter, userID string) error {
	var servers []serverInfo
	for v := range srv.hosts.All() {
		servers = append(servers, serverInfo{
			Name:        v.Name,
			Description: v.Description,
			LogoURL:     v.LogoURL,
			URL:         v.URL,
			NeedsOauth:  v.Config != nil,
			host:        v.Host,
		})
	}

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
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")

	type response struct {
		Servers []serverInfo `json:"servers"`
	}

	log.Ctx(ctx).Debug().
		Str("user-id", userID).
		Int("server-count", len(servers)).
		Msg("mcp/list-routes: sending response")

	return json.NewEncoder(w).Encode(response{
		Servers: servers,
	})
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
			_, err := srv.storage.GetUpstreamOAuth2Token(ctx, servers[i].host, userID)
			if err != nil && status.Code(err) != codes.NotFound {
				return fmt.Errorf("failed to get oauth2 token for user %s: %w", userID, err)
			}
			servers[i].Connected = err == nil
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
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	LogoURL     string `json:"logo_url,omitempty"`
	URL         string `json:"url"`
	Connected   bool   `json:"connected"`
	NeedsOauth  bool   `json:"needs_oauth"`
	host        string `json:"-"`
}
