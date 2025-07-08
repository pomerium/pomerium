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

	redirectURL, err := srv.checkClientRedirectURL(r)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("invalid client redirect URL")
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	claims, err := getClaimsFromRequest(r)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to get claims from request")
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	sessionID, ok := getSessionIDFromClaims(claims)
	if !ok {
		log.Ctx(ctx).Error().Err(err).Msg("session is not present, this is a misconfigured request")
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	userID, ok := getUserIDFromClaims(claims)
	if !ok {
		log.Ctx(ctx).Error().Err(err).Msg("user id is not present, this is a misconfigured request")
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	requiresUpstreamOAuth2Token := srv.hosts.HasOAuth2ConfigForHost(r.Host)
	if !requiresUpstreamOAuth2Token {
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return
	}

	token, err := srv.GetUpstreamOAuth2Token(ctx, r.Host, userID)
	if err != nil && status.Code(err) != codes.NotFound {
		log.Ctx(ctx).Error().Err(err).Msg("failed to get upstream oauth2 token")
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	if token != "" {
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return
	}

	req := &oauth21proto.AuthorizationRequest{
		ClientId:    InternalConnectClientID,
		RedirectUri: proto.String(redirectURL),
		SessionId:   sessionID,
		UserId:      userID,
	}
	authReqID, err := srv.storage.CreateAuthorizationRequest(ctx, req)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to create authorization request")
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	loginURL, ok := srv.hosts.GetLoginURLForHost(r.Host, authReqID)
	if ok {
		http.Redirect(w, r, loginURL, http.StatusFound)
		return
	}
	log.Ctx(ctx).Error().Str("host", r.Host).Msg("mcp/connect: must have login URL, this is a bug")
	http.Error(w, "internal server error", http.StatusInternalServerError)

	err = srv.storage.DeleteAuthorizationRequest(ctx, authReqID)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Str("id", authReqID).Msg("failed to delete authorization request after redirect")
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

// ConnectDelete is a helper method for MCP clients to purge the upstream OAuth2 token.
// DELETE /mcp/connect
// It will purge the upstream OAuth2 token and return 204 No Content.
func (srv *Handler) ConnectDelete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	claims, err := getClaimsFromRequest(r)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to get claims from request")
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	userID, ok := getUserIDFromClaims(claims)
	if !ok {
		log.Ctx(ctx).Error().Msg("user id is not present, this is a misconfigured request")
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	requiresUpstreamOAuth2Token := srv.hosts.HasOAuth2ConfigForHost(r.Host)
	if !requiresUpstreamOAuth2Token {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	err = srv.storage.DeleteUpstreamOAuth2Token(ctx, r.Host, userID)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to delete upstream oauth2 token")
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	log.Ctx(ctx).Debug().Str("host", r.Host).Str("user_id", userID).Msg("upstream oauth2 token purged")
	w.WriteHeader(http.StatusNoContent)
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

	claims, err := getClaimsFromRequest(r)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to get claims from request")
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	userID, ok := getUserIDFromClaims(claims)
	if !ok {
		log.Ctx(ctx).Error().Msg("user id is not present, this is a misconfigured request")
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	type disconnectRequest struct {
		Routes []string `json:"routes"`
	}

	var req disconnectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to decode disconnect request")
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if len(req.Routes) == 0 {
		log.Ctx(ctx).Error().Msg("no routes provided in disconnect request")
		http.Error(w, "no routes provided", http.StatusBadRequest)
		return
	}

	for _, routeURL := range req.Routes {
		parsedURL, err := url.Parse(routeURL)
		if err != nil {
			log.Ctx(ctx).Error().Err(err).Str("url", routeURL).Msg("failed to parse route URL")
			continue
		}

		host := parsedURL.Host
		if host == "" {
			log.Ctx(ctx).Error().Str("url", routeURL).Msg("route URL has no host")
			continue
		}

		requiresUpstreamOAuth2Token := srv.hosts.HasOAuth2ConfigForHost(host)
		if !requiresUpstreamOAuth2Token {
			log.Ctx(ctx).Debug().Str("host", host).Msg("host does not require oauth2 token - ignoring")
			continue
		}

		err = srv.storage.DeleteUpstreamOAuth2Token(ctx, host, userID)
		if err != nil {
			log.Ctx(ctx).Error().Err(err).Str("host", host).Msg("failed to delete upstream oauth2 token")
		}
	}

	err = srv.listMCPServersForUser(ctx, w, userID)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to list MCP servers after disconnect")
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
}
