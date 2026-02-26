package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

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

	// Static upstream_oauth2 config path
	if srv.hosts.HasOAuth2ConfigForHost(r.Host) {
		log.Ctx(ctx).Debug().
			Str("host", r.Host).
			Msg("mcp/connect: route has static upstream OAuth2 config")

		token, tokenErr := srv.GetUpstreamOAuth2Token(ctx, r.Host, userID)
		if tokenErr != nil && status.Code(tokenErr) != codes.NotFound {
			log.Ctx(ctx).Error().Err(tokenErr).Msg("mcp/connect: failed to get upstream oauth2 token")
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		if token != "" {
			log.Ctx(ctx).Debug().
				Str("redirect-url", redirectURL).
				Msg("mcp/connect: upstream token exists, redirecting to client")
			http.Redirect(w, r, redirectURL, http.StatusFound)
			return
		}

		log.Ctx(ctx).Debug().Msg("mcp/connect: no upstream token, initiating static upstream OAuth2 flow")

		req := &oauth21proto.AuthorizationRequest{
			ClientId:    InternalConnectClientID,
			RedirectUri: proto.String(redirectURL),
			SessionId:   sessionID,
			UserId:      userID,
		}
		authReqID, createErr := srv.storage.CreateAuthorizationRequest(ctx, req)
		if createErr != nil {
			log.Ctx(ctx).Error().Err(createErr).Msg("mcp/connect: failed to create authorization request")
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		loginURL, loginOK := srv.hosts.GetLoginURLForHost(r.Host, authReqID)
		if loginOK {
			log.Ctx(ctx).Debug().
				Str("login-url", loginURL).
				Msg("mcp/connect: redirecting to upstream OAuth2 login")
			http.Redirect(w, r, loginURL, http.StatusFound)
			return
		}
		log.Ctx(ctx).Error().Str("host", r.Host).Msg("mcp/connect: must have login URL, this is a bug")
		_ = srv.storage.DeleteAuthorizationRequest(ctx, authReqID)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// Auto-discovery path (no static upstream_oauth2 config)
	hostname := stripPort(r.Host)
	if srv.hosts.UsesAutoDiscovery(hostname) {
		info, ok := srv.hosts.GetServerHostInfo(hostname)
		if !ok || info.UpstreamURL == "" {
			log.Ctx(ctx).Error().
				Str("host", r.Host).
				Bool("info_found", ok).
				Str("upstream_url", info.UpstreamURL).
				Msg("mcp/connect: auto-discovery route has no upstream URL, route is misconfigured")
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		log.Ctx(ctx).Debug().
			Str("host", r.Host).
			Str("route_id", info.RouteID).
			Str("upstream_url", info.UpstreamURL).
			Msg("mcp/connect: route uses auto-discovery")

		// Check existing auto-discovery token
		if info.RouteID != "" && info.UpstreamURL != "" {
			token, tokenErr := srv.storage.GetUpstreamMCPToken(ctx, userID, info.RouteID, info.UpstreamURL)
			if tokenErr != nil && status.Code(tokenErr) != codes.NotFound {
				log.Ctx(ctx).Error().Err(tokenErr).Msg("mcp/connect: failed to get upstream MCP token")
				http.Error(w, "internal server error", http.StatusInternalServerError)
				return
			}
			if tokenErr == nil && token != nil && (token.ExpiresAt == nil || token.ExpiresAt.AsTime().After(time.Now())) {
				log.Ctx(ctx).Debug().
					Str("redirect-url", redirectURL).
					Msg("mcp/connect: valid upstream MCP token exists, redirecting to client")
				http.Redirect(w, r, redirectURL, http.StatusFound)
				return
			}
		}

		// Create AuthorizationRequest with InternalConnectClientID so the callback
		// chain redirects back to the client's redirect_url after token acquisition.
		req := &oauth21proto.AuthorizationRequest{
			ClientId:    InternalConnectClientID,
			RedirectUri: proto.String(redirectURL),
			SessionId:   sessionID,
			UserId:      userID,
		}
		authReqID, createErr := srv.storage.CreateAuthorizationRequest(ctx, req)
		if createErr != nil {
			log.Ctx(ctx).Error().Err(createErr).Msg("mcp/connect: failed to create authorization request")
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		// Resolve upstream auth via pending state or proactive discovery
		authURL, resolveErr := srv.resolveAutoDiscoveryAuth(ctx, &autoDiscoveryAuthParams{
			Hostname:  hostname,
			Host:      r.Host,
			UserID:    userID,
			AuthReqID: authReqID,
			Info:      info,
		})
		if resolveErr != nil {
			log.Ctx(ctx).Error().Err(resolveErr).Msg("mcp/connect: failed to resolve auto-discovery auth")
			_ = srv.storage.DeleteAuthorizationRequest(ctx, authReqID)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		if authURL != "" {
			log.Ctx(ctx).Debug().
				Str("auth-url", authURL).
				Msg("mcp/connect: redirecting to upstream AS for auto-discovery auth")
			http.Redirect(w, r, authURL, http.StatusFound)
			return
		}

		// No PRM found — upstream may not need OAuth, clean up auth request and redirect
		log.Ctx(ctx).Debug().
			Str("redirect-url", redirectURL).
			Msg("mcp/connect: auto-discovery found no PRM, redirecting to client")
		_ = srv.storage.DeleteAuthorizationRequest(ctx, authReqID)
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return
	}

	// No upstream OAuth needed (not a static config route and not an auto-discovery route)
	log.Ctx(ctx).Debug().
		Str("redirect-url", redirectURL).
		Msg("mcp/connect: no upstream OAuth required, redirecting to client")
	http.Redirect(w, r, redirectURL, http.StatusFound)
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
	if !srv.hosts.IsMCPClientForHost(stripPort(redirectURLParsed.Host)) {
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

		// Static upstream_oauth2 config: delete OAuth2 token
		if srv.hosts.HasOAuth2ConfigForHost(host) {
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
			continue
		}

		// Auto-discovery route: delete upstream MCP token and pending auth state
		hostname := stripPort(host)
		if srv.hosts.UsesAutoDiscovery(hostname) {
			info, ok := srv.hosts.GetServerHostInfo(hostname)
			if ok && info.RouteID != "" && info.UpstreamURL != "" {
				log.Ctx(ctx).Debug().
					Str("host", host).
					Str("route_id", info.RouteID).
					Str("upstream_url", info.UpstreamURL).
					Str("user-id", userID).
					Msg("mcp/disconnect: deleting upstream MCP token and pending auth state")

				if delErr := srv.storage.DeleteUpstreamMCPToken(ctx, userID, info.RouteID, info.UpstreamURL); delErr != nil {
					log.Ctx(ctx).Error().Err(delErr).Str("host", host).Msg("mcp/disconnect: failed to delete upstream MCP token")
				} else {
					disconnectedCount++
				}
				// Delete pending auth record for this user+host.
				if delErr := srv.storage.DeletePendingUpstreamAuth(ctx, userID, hostname); delErr != nil {
					log.Ctx(ctx).Warn().Err(delErr).Str("host", host).Msg("mcp/disconnect: failed to delete pending auth record")
				}
			}
			continue
		}

		log.Ctx(ctx).Debug().Str("host", host).Msg("mcp/disconnect: host does not require oauth token - ignoring")
		skippedCount++
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

// autoDiscoveryAuthParams holds parameters for resolveAutoDiscoveryAuth.
type autoDiscoveryAuthParams struct {
	Hostname  string // downstream hostname (port stripped)
	Host      string // downstream host (with optional port)
	UserID    string
	AuthReqID string
	Info      ServerHostInfo // route info with RouteID and UpstreamURL
}

// resolveAutoDiscoveryAuth checks for pending upstream auth or runs proactive PRM discovery
// to create PendingUpstreamAuth state for auto-discovery routes.
// Returns the upstream authorization URL to redirect the user to, or empty string if
// discovery found no PRM (upstream may not need OAuth).
func (srv *Handler) resolveAutoDiscoveryAuth(ctx context.Context, params *autoDiscoveryAuthParams) (string, error) {
	// Step 1: Check for pending upstream auth from ext_proc.
	pending, err := srv.storage.GetPendingUpstreamAuth(ctx, params.UserID, params.Hostname)
	if err == nil && pending != nil && (pending.ExpiresAt == nil || pending.ExpiresAt.AsTime().After(time.Now())) {
		log.Ctx(ctx).Info().
			Str("state_id", pending.StateId).
			Str("user_id", params.UserID).
			Str("host", params.Host).
			Str("auth_req_id", params.AuthReqID).
			Msg("mcp/auto-discovery: found pending upstream auth, reusing")

		// Link the authorization request to this pending upstream auth
		pending.AuthReqId = params.AuthReqID
		if putErr := srv.storage.PutPendingUpstreamAuth(ctx, pending); putErr != nil {
			return "", fmt.Errorf("failed to update pending upstream auth with auth_req_id: %w", putErr)
		}

		// Use ResourceParam (canonical resource from discovery) for the RFC 8707 resource
		// indicator. Falls back to stripQueryFromURL(OriginalUrl) for pending auth states
		// created before ResourceParam was added.
		resource := pending.GetResourceParam()
		if resource == "" {
			resource = stripQueryFromURL(pending.OriginalUrl)
		}
		authURL := buildAuthorizationURL(pending.AuthorizationEndpoint, &authorizationURLParams{
			ClientID:            pending.ClientId,
			RedirectURI:         pending.RedirectUri,
			Scopes:              pending.Scopes,
			State:               pending.StateId,
			CodeChallenge:       pending.PkceChallenge,
			CodeChallengeMethod: "S256",
			Resource:            resource,
		})
		return authURL, nil
	}

	// Step 2: Proactive discovery — fetch PRM to check if upstream needs OAuth.
	if params.Info.UpstreamURL == "" {
		return "", nil
	}

	setup, setupErr := runUpstreamOAuthSetup(ctx, srv.httpClient, params.Info.UpstreamURL, params.Host,
		WithFallbackAuthorizationURL(params.Info.AuthorizationServerURL),
		WithASMetadataDomainMatcher(srv.asMetadataDomainMatcher),
	)
	if setupErr != nil {
		// Non-fatal: upstream may not need OAuth.
		log.Ctx(ctx).Warn().Err(setupErr).
			Str("upstream_url", params.Info.UpstreamURL).
			Str("host", params.Host).
			Msg("mcp/auto-discovery: proactive upstream discovery failed, falling through")
		return "", nil
	}
	if setup == nil {
		return "", nil
	}

	// PRM found — create pending auth and return redirect URL
	verifier, challenge, pkceErr := generatePKCE()
	if pkceErr != nil {
		return "", fmt.Errorf("failed to generate PKCE: %w", pkceErr)
	}

	stateID, stateErr := generateRandomString(32)
	if stateErr != nil {
		return "", fmt.Errorf("failed to generate state: %w", stateErr)
	}

	now := time.Now()
	newPending := &oauth21proto.PendingUpstreamAuth{
		StateId:                   stateID,
		UserId:                    params.UserID,
		RouteId:                   params.Info.RouteID,
		UpstreamServer:            params.Info.UpstreamURL,
		PkceVerifier:              verifier,
		PkceChallenge:             challenge,
		Scopes:                    setup.Scopes,
		AuthorizationEndpoint:     setup.Discovery.AuthorizationEndpoint,
		TokenEndpoint:             setup.Discovery.TokenEndpoint,
		AuthorizationServerIssuer: setup.Discovery.Issuer,
		OriginalUrl:               params.Info.UpstreamURL,
		RedirectUri:               setup.RedirectURI,
		ClientId:                  setup.ClientID,
		DownstreamHost:            params.Host,
		AuthReqId:                 params.AuthReqID,
		CreatedAt:                 timestamppb.New(now),
		ExpiresAt:                 timestamppb.New(now.Add(pendingAuthExpiry)),
		ResourceParam:             setup.Discovery.Resource,
	}

	if putErr := srv.storage.PutPendingUpstreamAuth(ctx, newPending); putErr != nil {
		return "", fmt.Errorf("failed to store pending auth: %w", putErr)
	}

	authURL := buildAuthorizationURL(setup.Discovery.AuthorizationEndpoint, &authorizationURLParams{
		ClientID:            setup.ClientID,
		RedirectURI:         setup.RedirectURI,
		Scopes:              setup.Scopes,
		State:               stateID,
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		Resource:            setup.Discovery.Resource,
	})

	log.Ctx(ctx).Info().
		Str("state_id", stateID).
		Str("user_id", params.UserID).
		Str("host", params.Host).
		Str("auth_req_id", params.AuthReqID).
		Str("upstream_url", params.Info.UpstreamURL).
		Str("resource_param", setup.Discovery.Resource).
		Msg("mcp/auto-discovery: proactive upstream discovery succeeded, redirecting to upstream AS")

	return authURL, nil
}
