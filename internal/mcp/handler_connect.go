package mcp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/pomerium/pomerium/internal/log"
	oauth21proto "github.com/pomerium/pomerium/internal/oauth21/gen"
)

const InternalConnectClientID = "pomerium-connect-7549ebe0-a67d-4d2b-a90d-d0a483b85f72"

// ConnectGet is a helper method for MCP clients to ensure that the current user
// has an active upstream Oauth2 session for the route.
// GET /mcp/connect?redirect_url=<url>
// It will redirect to the provided redirect_url once the user has an active session.
func (srv *Handler) ConnectGet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	log.Ctx(ctx).Debug().
		Str("method", r.Method).
		Str("host", r.Host).
		Str("path", r.URL.Path).
		Str("query", r.URL.RawQuery).
		Msg("mcp/connect: request received")

	redirectURL, err := srv.checkClientRedirectURL(r)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("mcp/connect: invalid client redirect URL")
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	log.Ctx(ctx).Debug().
		Str("redirect-url", redirectURL).
		Msg("mcp/connect: validated redirect URL")

	claims, err := getClaimsFromRequest(r)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("mcp/connect: failed to get claims from request")
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	log.Ctx(ctx).Debug().
		Interface("claims", claims).
		Msg("mcp/connect: extracted JWT claims")

	sessionID, ok := getSessionIDFromClaims(claims)
	if !ok {
		log.Ctx(ctx).Error().Err(err).Msg("mcp/connect: session is not present, this is a misconfigured request")
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	userID, ok := getUserIDFromClaims(claims)
	if !ok {
		log.Ctx(ctx).Error().Err(err).Msg("mcp/connect: user id is not present, this is a misconfigured request")
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	log.Ctx(ctx).Debug().
		Str("session-id", sessionID).
		Str("user-id", userID).
		Msg("mcp/connect: extracted user info from claims")

	requiresUpstreamOAuth2Token := srv.hosts.HasOAuth2ConfigForHost(r.Host)
	log.Ctx(ctx).Debug().
		Str("host", r.Host).
		Bool("requires-upstream-oauth2", requiresUpstreamOAuth2Token).
		Msg("mcp/connect: checking upstream OAuth2 requirement")

	if !requiresUpstreamOAuth2Token {
		log.Ctx(ctx).Debug().
			Str("redirect-url", redirectURL).
			Msg("mcp/connect: no upstream OAuth2 required, redirecting to client")
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return
	}

	log.Ctx(ctx).Debug().
		Str("host", r.Host).
		Str("user-id", userID).
		Msg("mcp/connect: checking for existing upstream OAuth2 token")

	token, err := srv.GetUpstreamOAuth2Token(ctx, r.Host, userID)
	if err != nil && status.Code(err) != codes.NotFound {
		log.Ctx(ctx).Error().Err(err).Msg("mcp/connect: failed to get upstream oauth2 token")
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	log.Ctx(ctx).Debug().
		Bool("has-token", token != "").
		Msg("mcp/connect: upstream token check result")

	if token != "" {
		log.Ctx(ctx).Debug().
			Str("redirect-url", redirectURL).
			Msg("mcp/connect: upstream token exists, redirecting to client")
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return
	}

	log.Ctx(ctx).Debug().Msg("mcp/connect: no upstream token, initiating upstream OAuth2 flow")

	req := &oauth21proto.AuthorizationRequest{
		ClientId:    InternalConnectClientID,
		RedirectUri: proto.String(redirectURL),
		SessionId:   sessionID,
		UserId:      userID,
	}
	authReqID, err := srv.storage.CreateAuthorizationRequest(ctx, req)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("mcp/connect: failed to create authorization request")
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	log.Ctx(ctx).Debug().
		Str("auth-req-id", authReqID).
		Str("client-id", InternalConnectClientID).
		Msg("mcp/connect: created internal authorization request")

	loginURL, ok := srv.hosts.GetLoginURLForHost(r.Host, authReqID)
	if ok {
		log.Ctx(ctx).Debug().
			Str("login-url", loginURL).
			Msg("mcp/connect: redirecting to upstream OAuth2 login")
		http.Redirect(w, r, loginURL, http.StatusFound)
		return
	}
	log.Ctx(ctx).Error().Str("host", r.Host).Msg("mcp/connect: must have login URL, this is a bug")
	http.Error(w, "internal server error", http.StatusInternalServerError)

	err = srv.storage.DeleteAuthorizationRequest(ctx, authReqID)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Str("id", authReqID).Msg("mcp/connect: failed to delete authorization request after redirect")
	}
}

func (srv *Handler) checkClientRedirectURL(r *http.Request) (string, error) {
	redirectURL := r.URL.Query().Get("redirect_url")
	if redirectURL == "" {
		return "", fmt.Errorf("missing redirect_url query parameter")
	}

	redirectURLParsed, err := url.Parse(redirectURL)
	if err != nil {
		return "", fmt.Errorf("invalid redirect_url: %w", err)
	}
	if redirectURLParsed.Scheme != "https" {
		return "", fmt.Errorf("redirect_url must use https scheme")
	}
	if redirectURLParsed.Host == "" {
		return "", fmt.Errorf("redirect_url must have a host")
	}
	if !srv.hosts.IsMCPClientForHost(redirectURLParsed.Host) {
		return "", fmt.Errorf("redirect_url host %s is not a MCP client", redirectURLParsed.Host)
	}
	return redirectURL, nil
}

// DisconnectRoutes is a bulk helper method for MCP clients to purge upstream OAuth2 tokens
// for multiple routes. This is necessary because frontend clients cannot execute direct
// DELETE calls to other routes.
//
// POST /mcp/routes/disconnect
//
// Request body should contain a JSON object with a "routes" array:
//
//	{
//	  "routes": ["https://server1.example.com", "https://server2.example.com"]
//	}
//
// Response returns the same format as GET /mcp/routes, showing the updated connection status:
//
//	{
//	  "servers": [
//	    {
//	      "name": "Server 1",
//	      "url": "https://server1.example.com",
//	      "connected": false,
//	      "needs_oauth": true
//	    },
//	    {
//	      "name": "Server 2",
//	      "url": "https://server2.example.com",
//	      "connected": false,
//	      "needs_oauth": true
//	    }
//	  ]
//	}
func (srv *Handler) DisconnectRoutes(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	log.Ctx(ctx).Debug().
		Str("method", r.Method).
		Str("host", r.Host).
		Str("path", r.URL.Path).
		Msg("mcp/disconnect: request received")

	claims, err := getClaimsFromRequest(r)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("mcp/disconnect: failed to get claims from request")
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	userID, ok := getUserIDFromClaims(claims)
	if !ok {
		log.Ctx(ctx).Error().Msg("mcp/disconnect: user id is not present, this is a misconfigured request")
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	log.Ctx(ctx).Debug().
		Str("user-id", userID).
		Msg("mcp/disconnect: extracted user info from claims")

	type disconnectRequest struct {
		Routes []string `json:"routes"`
	}

	var req disconnectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("mcp/disconnect: failed to decode disconnect request")
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	log.Ctx(ctx).Debug().
		Strs("routes", req.Routes).
		Int("route-count", len(req.Routes)).
		Msg("mcp/disconnect: parsed disconnect request")

	if len(req.Routes) == 0 {
		log.Ctx(ctx).Error().Msg("mcp/disconnect: no routes provided in disconnect request")
		http.Error(w, "no routes provided", http.StatusBadRequest)
		return
	}

	disconnectedCount := 0
	skippedCount := 0
	for _, routeURL := range req.Routes {
		parsedURL, err := url.Parse(routeURL)
		if err != nil {
			log.Ctx(ctx).Error().Err(err).Str("url", routeURL).Msg("mcp/disconnect: failed to parse route URL")
			skippedCount++
			continue
		}

		host := parsedURL.Host
		if host == "" {
			log.Ctx(ctx).Error().Str("url", routeURL).Msg("mcp/disconnect: route URL has no host")
			skippedCount++
			continue
		}

		requiresUpstreamOAuth2Token := srv.hosts.HasOAuth2ConfigForHost(host)
		if !requiresUpstreamOAuth2Token {
			log.Ctx(ctx).Debug().Str("host", host).Msg("mcp/disconnect: host does not require oauth2 token - ignoring")
			skippedCount++
			continue
		}

		log.Ctx(ctx).Debug().
			Str("host", host).
			Str("user-id", userID).
			Msg("mcp/disconnect: deleting upstream OAuth2 token")

		err = srv.storage.DeleteUpstreamOAuth2Token(ctx, host, userID)
		if err != nil {
			log.Ctx(ctx).Error().Err(err).Str("host", host).Msg("mcp/disconnect: failed to delete upstream oauth2 token")
		} else {
			log.Ctx(ctx).Debug().Str("host", host).Msg("mcp/disconnect: upstream OAuth2 token deleted")
			disconnectedCount++
		}
	}

	log.Ctx(ctx).Info().
		Str("user-id", userID).
		Int("disconnected", disconnectedCount).
		Int("skipped", skippedCount).
		Msg("mcp/disconnect: disconnect operation completed")

	err = srv.listMCPServersForUser(ctx, w, userID)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("mcp/disconnect: failed to list MCP servers after disconnect")
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
}
