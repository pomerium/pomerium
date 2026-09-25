package mcp

import (
	"context"
	"errors"
	"net/http"
	"net/url"

	"github.com/pomerium/pomerium/internal/log"
)

// RefreshRoutes performs an upstream OAuth2 refresh_token grant for the current user on
// each of the supplied routes, regardless of whether the stored access token is still valid.
// It exists so the routes portal can refresh a route's upstream token on demand; frontend
// clients cannot call other routes directly.
//
// POST /.pomerium/mcp/routes/refresh
//
// The request body is the `{"routes": [...]}` shape shared with routes/disconnect, and the
// response is the GET /.pomerium/mcp/routes listing plus an optional "errors" map keyed by
// the route URL exactly as it was sent.
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

	routes, ok := decodeRoutesRequest(w, r, "mcp/refresh")
	if !ok {
		return
	}

	routeErrors := map[string]string{}
	for _, routeURL := range routes {
		if err := srv.refreshRoute(ctx, userID, routeURL); err != nil {
			routeErrors[routeURL] = err.Error()
		}
	}

	log.Ctx(ctx).Info().
		Str("user-id", userID).
		Int("requested", len(routes)).
		Int("failed", len(routeErrors)).
		Msg("mcp/refresh: refresh operation completed")

	if err := srv.listMCPServersForUser(ctx, w, userID, routeErrors); err != nil {
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
	if isNotFound(err) {
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

	refreshed, err := forceRefreshUpstreamMCPToken(
		ctx, srv.storage, srv.httpClient, &srv.singleFlight,
		token, info.ConfigClientSecret(),
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

	// refreshUpstreamMCPToken already logs the successful refresh with the new expiry.
	return nil
}
