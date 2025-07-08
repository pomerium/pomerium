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
	if r.Method != http.MethodGet {
		http.Error(w, "invalid method", http.StatusMethodNotAllowed)
		return
	}

	err := srv.listMCPServers(w, r)
	if err != nil {
		log.Ctx(r.Context()).Error().Err(err).Msg("failed to list MCP servers")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (srv *Handler) listMCPServers(w http.ResponseWriter, r *http.Request) error {
	claims, err := getClaimsFromRequest(r)
	if err != nil {
		return fmt.Errorf("failed to get claims from request: %w", err)
	}

	userID, ok := getUserIDFromClaims(claims)
	if !ok {
		return fmt.Errorf("user id is not present in claims")
	}

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

	servers, err = srv.checkHostsConnectedForUser(r.Context(), userID, servers)
	if err != nil {
		return fmt.Errorf("failed to check hosts connected for user %s: %w", userID, err)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")

	type response struct {
		Servers []serverInfo `json:"servers"`
	}

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
