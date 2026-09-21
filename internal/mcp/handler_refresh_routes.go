package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/pomerium/pomerium/internal/log"
	oauth21proto "github.com/pomerium/pomerium/internal/oauth21/gen"
)

// RefreshRoutes performs an upstream OAuth2 refresh_token grant for the current user on
// each of the supplied routes, regardless of whether the stored access token is still valid.
// It exists so the routes portal can refresh a route's upstream token on demand; frontend
// clients cannot call other routes directly.
//
// POST /.pomerium/mcp/routes/refresh
//
// Request body mirrors routes/disconnect:
//
//	{
//	  "routes": ["https://server1.example.com", "https://server2.example.com"]
//	}
//
// The response is the same listing as GET /.pomerium/mcp/routes, plus an optional
// per-route error map keyed by the route URL exactly as it was sent:
//
//	{
//	  "servers": [{"name": "Server 1", "url": "https://server1.example.com", "connected": true, ...}],
//	  "errors": {"https://server2.example.com": "route is not connected"}
//	}
//
// The status code is 200 whenever the request itself was well-formed, even if some or all
// routes failed to refresh. A permanent rejection by the upstream authorization server
// (4xx) clears the stored token, so the route reads back as not connected. A transient
// failure preserves the token and is reported in "errors".
func (srv *Handler) RefreshRoutes(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	log.Ctx(ctx).Debug().
		Str("method", r.Method).
		Str("host", r.Host).
		Str("path", r.URL.Path).
		Msg("mcp/refresh: request received")

	claims, err := getClaimsFromRequest(r)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("mcp/refresh: failed to get claims from request")
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}

	userID, ok := getUserIDFromClaims(claims)
	if !ok {
		log.Ctx(ctx).Error().Msg("mcp/refresh: user id is not present in claims")
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}

	var req struct {
		Routes []string `json:"routes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("mcp/refresh: failed to decode refresh request")
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if len(req.Routes) == 0 {
		log.Ctx(ctx).Error().Msg("mcp/refresh: no routes provided in refresh request")
		http.Error(w, "no routes provided", http.StatusBadRequest)
		return
	}

	log.Ctx(ctx).Debug().
		Str("user-id", userID).
		Strs("routes", req.Routes).
		Msg("mcp/refresh: parsed refresh request")

	var routeErrors map[string]string
	for _, routeURL := range req.Routes {
		if err := srv.refreshRoute(ctx, userID, routeURL); err != nil {
			if routeErrors == nil {
				routeErrors = make(map[string]string)
			}
			routeErrors[routeURL] = err.Error()
		}
	}

	log.Ctx(ctx).Info().
		Str("user-id", userID).
		Int("requested", len(req.Routes)).
		Int("failed", len(routeErrors)).
		Msg("mcp/refresh: refresh operation completed")

	if err := srv.listMCPServersForUserWithErrors(ctx, w, userID, routeErrors); err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("mcp/refresh: failed to list MCP servers after refresh")
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
}

// refreshRoute refreshes the upstream token for a single route. The returned error is
// user-facing: it is reported back to the caller in the response's "errors" map.
func (srv *Handler) refreshRoute(ctx context.Context, userID, routeURL string) error {
	parsedURL, err := url.Parse(routeURL)
	if err != nil || parsedURL.Host == "" {
		log.Ctx(ctx).Error().Err(err).Str("url", routeURL).Msg("mcp/refresh: invalid route URL")
		return errors.New("invalid route URL")
	}

	hostname := stripPort(parsedURL.Host)
	info, ok := srv.hosts.GetServerHostInfo(hostname)
	if !ok || info.RouteID == "" || info.UpstreamURL == "" {
		return errors.New("route does not use an upstream OAuth token")
	}

	token, err := srv.storage.GetUpstreamMCPToken(ctx, userID, info.RouteID, info.UpstreamURL)
	if status.Code(err) == codes.NotFound {
		return errors.New("route is not connected")
	} else if err != nil {
		log.Ctx(ctx).Error().Err(err).
			Str("user_id", userID).
			Str("route_id", info.RouteID).
			Msg("mcp/refresh: failed to get upstream MCP token")
		return errors.New("failed to load the stored upstream token")
	}
	if token == nil {
		return errors.New("route is not connected")
	}

	var configClientSecret string
	if info.UpstreamOAuth2 != nil {
		configClientSecret = info.UpstreamOAuth2.ClientSecret
	}
	refreshed, err := forceRefreshUpstreamMCPToken(
		ctx, srv.storage, srv.httpClient, &srv.singleFlight,
		token, configClientSecret,
	)
	switch {
	case errors.Is(err, errTokenNotRefreshable):
		return errors.New("token cannot be refreshed: the upstream authorization server did not issue a refresh token")
	case err != nil:
		log.Ctx(ctx).Warn().Err(err).
			Str("user_id", userID).
			Str("route_id", info.RouteID).
			Msg("mcp/refresh: transient upstream token refresh failure")
		return errors.New("temporary failure refreshing the upstream token, try again")
	case refreshed == nil:
		// Permanent failure: the stale token has been cleared, re-authorization is required.
		return errors.New("the upstream authorization server rejected the refresh token, reconnect required")
	}

	logRefreshedToken(ctx, userID, info.RouteID, refreshed)
	return nil
}

func logRefreshedToken(ctx context.Context, userID, routeID string, token *oauth21proto.UpstreamMCPToken) {
	event := log.Ctx(ctx).Debug().
		Str("user_id", userID).
		Str("route_id", routeID)
	if t := token.GetExpiresAt(); t != nil {
		event = event.Time("expires_at", t.AsTime())
	}
	event.Msg("mcp/refresh: upstream token refreshed")
}
