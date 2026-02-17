package mcp

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/log"
	oauth21proto "github.com/pomerium/pomerium/internal/oauth21/gen"
)

// ClientOAuthCallback handles the redirect back from an upstream authorization server
// after the user has granted consent. It exchanges the authorization code for tokens,
// stores them, and redirects back to the original URL that triggered the 401.
func (srv *Handler) ClientOAuthCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	log.Ctx(ctx).Debug().
		Str("method", r.Method).
		Str("host", r.Host).
		Str("path", r.URL.Path).
		Str("query", r.URL.RawQuery).
		Msg("mcp/client-oauth-callback: request received")

	code := r.URL.Query().Get("code")
	stateID := r.URL.Query().Get("state")

	if code == "" || stateID == "" {
		errParam := r.URL.Query().Get("error")
		errDesc := r.URL.Query().Get("error_description")
		if errParam != "" {
			log.Ctx(ctx).Error().
				Str("error", errParam).
				Str("error_description", errDesc).
				Msg("mcp/client-oauth-callback: upstream AS returned error")
			http.Error(w, "Authorization failed", http.StatusBadRequest)
			return
		}
		log.Ctx(ctx).Error().
			Bool("has_code", code != "").
			Bool("has_state", stateID != "").
			Msg("mcp/client-oauth-callback: missing code or state")
		http.Error(w, "Invalid callback: missing code or state", http.StatusBadRequest)
		return
	}

	// Look up pending authorization state
	pending, err := srv.storage.GetPendingUpstreamAuth(ctx, stateID)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).
			Str("state_id", stateID).
			Msg("mcp/client-oauth-callback: failed to get pending auth state")
		http.Error(w, "Invalid or expired state", http.StatusBadRequest)
		return
	}

	// Check expiry
	if pending.ExpiresAt != nil && pending.ExpiresAt.AsTime().Before(time.Now()) {
		log.Ctx(ctx).Error().
			Str("state_id", stateID).
			Time("expired_at", pending.ExpiresAt.AsTime()).
			Msg("mcp/client-oauth-callback: pending auth state expired")
		if delErr := srv.storage.DeletePendingUpstreamAuth(ctx, stateID); delErr != nil {
			log.Ctx(ctx).Warn().Err(delErr).Str("state_id", stateID).Msg("mcp/client-oauth-callback: failed to clean up expired pending auth state")
		}
		http.Error(w, "Authorization state expired, please retry", http.StatusBadRequest)
		return
	}

	// Exchange authorization code for tokens
	data := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {pending.RedirectUri},
		"client_id":     {pending.ClientId},
		"code_verifier": {pending.PkceVerifier},
	}
	if pending.ClientSecret != "" {
		data.Set("client_secret", pending.ClientSecret)
	}
	if pending.UpstreamServer != "" {
		data.Set("resource", pending.UpstreamServer)
	}

	tokenReq, err := http.NewRequestWithContext(ctx, http.MethodPost, pending.TokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("mcp/client-oauth-callback: failed to create token request")
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	tokenResp, err := exchangeToken(srv.clientOAuthHTTPClient(), tokenReq)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("mcp/client-oauth-callback: token exchange failed")
		_ = srv.storage.DeletePendingUpstreamAuth(ctx, stateID)
		http.Error(w, "Token exchange failed", http.StatusBadGateway)
		return
	}

	// Store the upstream MCP token
	now := time.Now()
	upstreamToken := &oauth21proto.UpstreamMCPToken{
		UserId:                    pending.UserId,
		RouteId:                   pending.RouteId,
		UpstreamServer:            pending.UpstreamServer,
		AccessToken:               tokenResp.AccessToken,
		RefreshToken:              tokenResp.RefreshToken,
		TokenType:                 tokenResp.TokenType,
		IssuedAt:                  timestamppb.New(now),
		Scopes:                    pending.Scopes,
		Audience:                  pending.ClientId,
		AuthorizationServerIssuer: pending.AuthorizationServerIssuer,
		TokenEndpoint:             pending.TokenEndpoint,
	}

	if tokenResp.ExpiresIn > 0 {
		upstreamToken.ExpiresAt = timestamppb.New(now.Add(time.Duration(tokenResp.ExpiresIn) * time.Second))
	}

	if err := srv.storage.PutUpstreamMCPToken(ctx, upstreamToken); err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("mcp/client-oauth-callback: failed to store upstream token")
		http.Error(w, "Failed to store token", http.StatusInternalServerError)
		return
	}

	if delErr := srv.storage.DeletePendingUpstreamAuth(ctx, stateID); delErr != nil {
		log.Ctx(ctx).Warn().Err(delErr).Str("state_id", stateID).Msg("mcp/client-oauth-callback: failed to clean up pending auth state")
	}

	log.Ctx(ctx).Info().
		Str("user_id", pending.UserId).
		Str("route_id", pending.RouteId).
		Str("upstream_server", pending.UpstreamServer).
		Str("auth_req_id", pending.AuthReqId).
		Msg("mcp/client-oauth-callback: upstream token stored")

	// If the Authorize endpoint linked an authorization request, complete the MCP OAuth flow
	// by issuing an authorization code back to the MCP client (via AuthorizationResponse).
	if pending.AuthReqId != "" {
		authReq, err := srv.storage.GetAuthorizationRequest(ctx, pending.AuthReqId)
		if err != nil {
			log.Ctx(ctx).Error().Err(err).
				Str("auth_req_id", pending.AuthReqId).
				Msg("mcp/client-oauth-callback: failed to get linked authorization request")
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
		log.Ctx(ctx).Info().
			Str("auth_req_id", pending.AuthReqId).
			Str("client_id", authReq.GetClientId()).
			Msg("mcp/client-oauth-callback: completing MCP authorization flow")
		srv.AuthorizationResponse(ctx, w, r, pending.AuthReqId, authReq)
		return
	}

	// Fallback: redirect to the original URL (legacy behavior for non-MCP clients)
	log.Ctx(ctx).Info().Msg("mcp/client-oauth-callback: no linked auth request, redirecting to original URL")
	http.Redirect(w, r, pending.OriginalUrl, http.StatusFound)
}

// clientOAuthHTTPClient returns the HTTP client to use for upstream OAuth token exchange.
func (srv *Handler) clientOAuthHTTPClient() *http.Client {
	return http.DefaultClient
}
