package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/log"
	oauth21proto "github.com/pomerium/pomerium/internal/oauth21/gen"
	rfc7591v1 "github.com/pomerium/pomerium/internal/rfc7591"
	"github.com/pomerium/pomerium/pkg/telemetry/requestid"
)

const InternalConnectClientID = "pomerium-connect-7549ebe0-a67d-4d2b-a90d-d0a483b85f72"

// DiscoveryError indicates that upstream OAuth discovery failed during the connect or
// authorize flow. This is distinct from a hard error — the upstream may not need OAuth —
// but the caller should surface the failure reason to the user if possible.
type DiscoveryError struct {
	Err error
}

func (e *DiscoveryError) Error() string { return e.Err.Error() }
func (e *DiscoveryError) Unwrap() error { return e.Err }

// ConnectGet is a helper method for MCP clients to ensure that the current user
// has an active upstream OAuth2 session for the route.
// GET /.pomerium/mcp/connect?redirect_url=<url>
// It will redirect to the provided redirect_url once the user has an active session.
// Supports both static upstream_oauth2 config and auto-discovery flows.
func (srv *Handler) ConnectGet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	log.Ctx(ctx).Debug().
		Str("method", r.Method).
		Str("host", r.Host).
		Str("path", r.URL.Path).
		Str("query", r.URL.RawQuery).
		Msg("mcp/connect: request received")

	redirectURL := r.URL.Query().Get("redirect_url")
	if !srv.isValidRedirectURL(redirectURL, r.Host) {
		log.Ctx(ctx).Error().
			Str("redirect_url", redirectURL).
			Str("host", r.Host).
			Msg("mcp/connect: invalid client redirect URL")
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
		log.Ctx(ctx).Error().Msg("mcp/connect: session is not present, this is a misconfigured request")
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	userID, ok := getUserIDFromClaims(claims)
	if !ok {
		log.Ctx(ctx).Error().Msg("mcp/connect: user id is not present, this is a misconfigured request")
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	log.Ctx(ctx).Debug().
		Str("session-id", sessionID).
		Str("user-id", userID).
		Msg("mcp/connect: extracted user info from claims")

	// Unified upstream OAuth path — handles static, pre-registered, and auto-discovery routes.
	hostname := stripPort(r.Host)
	info, infoOK := srv.hosts.GetServerHostInfo(hostname)
	if infoOK && info.UpstreamURL != "" {
		if info.RouteID == "" {
			log.Ctx(ctx).Error().
				Str("host", r.Host).
				Str("upstream_url", info.UpstreamURL).
				Msg("mcp/connect: route has no route ID, misconfigured")
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		log.Ctx(ctx).Debug().
			Str("host", r.Host).
			Str("route_id", info.RouteID).
			Str("upstream_url", info.UpstreamURL).
			Bool("has_upstream_oauth2", info.UpstreamOAuth2 != nil).
			Msg("mcp/connect: checking upstream token")

		// Check existing upstream token
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
			if delErr := srv.storage.DeleteAuthorizationRequest(ctx, authReqID); delErr != nil {
				log.Ctx(ctx).Warn().Err(delErr).Str("id", authReqID).Msg("mcp/connect: failed to clean up authorization request")
			}

			// Discovery errors are non-fatal but should be surfaced to the user
			// by appending error info to the redirect URL.
			var discoveryErr *DiscoveryError
			if errors.As(resolveErr, &discoveryErr) {
				reqID := requestid.FromContext(ctx)
				log.Ctx(ctx).Warn().Err(resolveErr).
					Str("redirect-url", redirectURL).
					Str("request-id", reqID).
					Msg("mcp/connect: discovery failed, redirecting with error")
				http.Redirect(w, r, appendConnectError(redirectURL,
					fmt.Sprintf("MCP connection failed. Ask your administrator to check logs for request ID: %s", reqID)),
					http.StatusFound)
				return
			}

			log.Ctx(ctx).Error().Err(resolveErr).Msg("mcp/connect: failed to resolve auto-discovery auth")
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
		if delErr := srv.storage.DeleteAuthorizationRequest(ctx, authReqID); delErr != nil {
			log.Ctx(ctx).Warn().Err(delErr).Str("id", authReqID).Msg("mcp/connect: failed to clean up authorization request")
		}
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return
	}

	// No upstream OAuth needed (not a static config route and not an auto-discovery route)
	log.Ctx(ctx).Debug().
		Str("redirect-url", redirectURL).
		Msg("mcp/connect: no upstream OAuth required, redirecting to client")
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// appendConnectError appends error query parameters to a redirect URL so that
// the target page (e.g. the routes portal) can display the error to the user.
func appendConnectError(redirectURL, description string) string {
	u, err := url.Parse(redirectURL)
	if err != nil {
		log.Error().Err(err).Str("redirect_url", redirectURL).Msg("mcp/connect: failed to parse redirect URL for error append")
		return redirectURL
	}
	q := u.Query()
	q.Set("connect_error", description)
	u.RawQuery = q.Encode()
	return u.String()
}

// isValidRedirectURL checks whether redirectURL is safe for use in an HTTP redirect.
// It requires HTTPS, a non-empty host, and that the host is either the request's
// own host or a registered MCP client host.
//
// The function name intentionally matches CodeQL's barrier-guard pattern for
// go/unvalidated-url-redirection so that the `true` return value is recognized
// as proof that redirectURL has been validated.
func (srv *Handler) isValidRedirectURL(redirectURL string, requestHost string) bool {
	if redirectURL == "" {
		return false
	}
	parsed, err := url.Parse(redirectURL)
	if err != nil {
		return false
	}
	if parsed.Scheme != "https" {
		return false
	}
	if parsed.Host == "" {
		return false
	}
	// Allow redirects back to the same host (e.g. the routes portal on the MCP server host).
	redirectHostname := stripPort(parsed.Host)
	if redirectHostname != stripPort(requestHost) &&
		!srv.hosts.IsMCPClientForHost(redirectHostname) {
		return false
	}
	return true
}

// DisconnectRoutes is a bulk helper method for MCP clients to purge upstream OAuth2 tokens
// for multiple routes. This is necessary because frontend clients cannot execute direct
// DELETE calls to other routes.
//
// POST /.pomerium/mcp/routes/disconnect
//
// Request body should contain a JSON object with a "routes" array:
//
//	{
//	  "routes": ["https://server1.example.com", "https://server2.example.com"]
//	}
//
// Response returns the same format as GET /.pomerium/mcp/routes, showing the updated connection status:
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

		// Unified path: delete upstream MCP token and pending auth state
		hostname := stripPort(host)
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
			if delErr := srv.storage.DeletePendingUpstreamAuth(ctx, userID, hostname); delErr != nil {
				log.Ctx(ctx).Warn().Err(delErr).Str("host", host).Msg("mcp/disconnect: failed to delete pending auth record")
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
	if err != nil {
		log.Ctx(ctx).Warn().Err(err).
			Str("user_id", params.UserID).
			Str("hostname", params.Hostname).
			Msg("mcp/auto-discovery: failed to get pending upstream auth, proceeding to proactive discovery")
	}
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
		var extraParams map[string]string
		if oa := params.Info.UpstreamOAuth2; oa != nil {
			extraParams = oa.AuthorizationURLParams
		}
		authURL, err := buildAuthorizationURL(pending.AuthorizationEndpoint, &authorizationURLParams{
			ClientID:            pending.ClientId,
			RedirectURI:         pending.RedirectUri,
			Scopes:              pending.Scopes,
			State:               pending.StateId,
			CodeChallenge:       pending.PkceChallenge,
			CodeChallengeMethod: "S256",
			Resource:            resource,
			ExtraParams:         extraParams,
		})
		if err != nil {
			return "", fmt.Errorf("building authorization URL: %w", err)
		}
		return authURL, nil
	}

	// Step 2: Proactive discovery — fetch PRM to check if upstream needs OAuth.
	if params.Info.UpstreamURL == "" {
		return "", nil
	}

	setupOpts := []UpstreamOAuthSetupOption{
		WithFallbackAuthorizationURL(params.Info.AuthorizationServerURL),
		WithASMetadataDomainMatcher(srv.asMetadataDomainMatcher),
		WithAllowDCRFallback(true),
	}
	setupOpts = append(setupOpts, upstreamOAuthSetupOptsFromConfig(params.Info.UpstreamOAuth2)...)
	setup, setupErr := runUpstreamOAuthSetup(ctx, srv.httpClient, params.Info.UpstreamURL, params.Host, setupOpts...)
	if setupErr != nil {
		// Discovery failed — upstream may not need OAuth, or there's a real config issue.
		log.Ctx(ctx).Warn().Err(setupErr).
			Str("upstream_url", params.Info.UpstreamURL).
			Str("host", params.Host).
			Msg("mcp/auto-discovery: proactive upstream discovery failed, falling through")
		return "", &DiscoveryError{Err: setupErr}
	}
	if setup == nil {
		return "", nil
	}

	if setup.ClientID == "" {
		registeredClient, regErr := srv.getOrRegisterUpstreamOAuthClient(ctx, setup.Discovery, params.Host, setup.RedirectURI)
		if regErr != nil {
			return "", fmt.Errorf("failed to register upstream oauth client: %w", regErr)
		}
		setup.ClientID = registeredClient.GetClientId()
		setup.ClientSecret = registeredClient.GetClientSecret()
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

	newPending := newPendingUpstreamAuth(newPendingUpstreamAuthParams{
		StateID:     stateID,
		UserID:      params.UserID,
		RouteID:     params.Info.RouteID,
		UpstreamURL: params.Info.UpstreamURL,
		OriginalURL: params.Info.UpstreamURL,
		Host:        params.Host,
		AuthReqID:   params.AuthReqID,
		Verifier:    verifier,
		Challenge:   challenge,
	}, setup)

	if putErr := srv.storage.PutPendingUpstreamAuth(ctx, newPending); putErr != nil {
		return "", fmt.Errorf("failed to store pending auth: %w", putErr)
	}

	var newExtraParams map[string]string
	if oa := params.Info.UpstreamOAuth2; oa != nil {
		newExtraParams = oa.AuthorizationURLParams
	}
	authURL, err := buildAuthorizationURL(setup.Discovery.AuthorizationEndpoint, &authorizationURLParams{
		ClientID:            setup.ClientID,
		RedirectURI:         setup.RedirectURI,
		Scopes:              setup.Scopes,
		State:               stateID,
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		Resource:            setup.Discovery.Resource,
		ExtraParams:         newExtraParams,
	})
	if err != nil {
		return "", fmt.Errorf("building authorization URL: %w", err)
	}

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

func (srv *Handler) getOrRegisterUpstreamOAuthClient(
	ctx context.Context,
	discovery *discoveryResult,
	downstreamHost string,
	redirectURI string,
) (*oauth21proto.UpstreamOAuthClient, error) {
	if discovery == nil {
		return nil, fmt.Errorf("discovery result is nil")
	}
	if discovery.RegistrationEndpoint == "" {
		return nil, fmt.Errorf("upstream authorization server %s does not advertise a registration_endpoint for dynamic client registration", discovery.Issuer)
	}

	if client, err := srv.storage.GetUpstreamOAuthClient(ctx, discovery.Issuer, downstreamHost); err == nil {
		if client.ClientId != "" {
			return client, nil
		}
	} else {
		log.Ctx(ctx).Warn().Err(err).Str("issuer", discovery.Issuer).Str("downstream_host", downstreamHost).Msg("mcp/auto-discovery: DCR cache lookup failed, proceeding to registration")
	}

	sfKey := fmt.Sprintf("dcr:%s:%s", discovery.Issuer, downstreamHost)
	result, err, _ := srv.hostsSingleFlight.Do(sfKey, func() (any, error) {
		if client, cacheErr := srv.storage.GetUpstreamOAuthClient(ctx, discovery.Issuer, downstreamHost); cacheErr == nil {
			if client.ClientId != "" {
				return client, nil
			}
		} else {
			log.Ctx(ctx).Warn().Err(cacheErr).Str("issuer", discovery.Issuer).Str("downstream_host", downstreamHost).Msg("mcp/auto-discovery: DCR cache re-check failed inside singleflight, proceeding to registration")
		}

		registeredClient, registerErr := srv.registerWithUpstreamAS(ctx, discovery, downstreamHost, redirectURI)
		if registerErr != nil {
			return nil, registerErr
		}

		if registeredClient.GetClientId() == "" {
			return nil, fmt.Errorf("upstream AS %s returned empty client_id from dynamic client registration", discovery.Issuer)
		}

		if putErr := srv.storage.PutUpstreamOAuthClient(ctx, registeredClient); putErr != nil {
			return nil, fmt.Errorf("storing dynamic client registration: %w", putErr)
		}

		return registeredClient, nil
	})
	if err != nil {
		return nil, err
	}
	client, ok := result.(*oauth21proto.UpstreamOAuthClient)
	if !ok {
		return nil, fmt.Errorf("unexpected singleflight result type: %T", result)
	}
	return client, nil
}

func (srv *Handler) registerWithUpstreamAS(
	ctx context.Context,
	discovery *discoveryResult,
	downstreamHost string,
	redirectURI string,
) (*oauth21proto.UpstreamOAuthClient, error) {
	requestMetadata := &rfc7591v1.Metadata{
		RedirectUris:            []string{redirectURI},
		TokenEndpointAuthMethod: proto.String(rfc7591v1.TokenEndpointAuthMethodNone),
		GrantTypes:              []string{rfc7591v1.GrantTypesAuthorizationCode, rfc7591v1.GrantTypesRefreshToken},
		ResponseTypes:           []string{rfc7591v1.ResponseTypesCode},
		ClientName:              proto.String("Pomerium MCP Proxy"),
	}

	body, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(requestMetadata)
	if err != nil {
		return nil, fmt.Errorf("marshaling registration request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, discovery.RegistrationEndpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating registration request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := srv.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sending registration request: %w", err)
	}
	defer resp.Body.Close()

	const maxRegistrationResponseBytes = 1 << 20 // 1 MB
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxRegistrationResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("reading registration response: %w", err)
	}

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("registration endpoint %s returned status %d: %s", discovery.RegistrationEndpoint, resp.StatusCode, string(respBody))
	}

	registrationResponse, err := rfc7591v1.ParseRegistrationResponse(respBody)
	if err != nil {
		return nil, fmt.Errorf("parsing registration response: %w", err)
	}

	registeredClient := &oauth21proto.UpstreamOAuthClient{
		Issuer:               discovery.Issuer,
		DownstreamHost:       downstreamHost,
		ClientId:             registrationResponse.GetClientId(),
		ClientSecret:         registrationResponse.GetClientSecret(),
		RedirectUri:          redirectURI,
		RegistrationEndpoint: discovery.RegistrationEndpoint,
		CreatedAt:            timestamppb.Now(),
	}

	log.Ctx(ctx).Info().
		Str("issuer", discovery.Issuer).
		Str("downstream_host", downstreamHost).
		Str("registration_endpoint", discovery.RegistrationEndpoint).
		Str("client_id", registeredClient.ClientId).
		Bool("has_client_secret", registeredClient.ClientSecret != "").
		Msg("mcp/auto-discovery: dynamic client registration succeeded")

	return registeredClient, nil
}
