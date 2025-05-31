package mcp

import (
	"fmt"
	"net/http"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/pomerium/pomerium/internal/log"
	oauth21proto "github.com/pomerium/pomerium/internal/oauth21/gen"
)

// Connect is a helper method for MCP clients to ensure that the current user
// has an active upstream Oauth2 session for the route.
func (srv *Handler) Connect(w http.ResponseWriter, r *http.Request) {
	fmt.Println("CONNECT ", r.Method, r.URL.Path)
	if r.Method != http.MethodGet {
		http.Error(w, "invalid method", http.StatusMethodNotAllowed)
		return
	}

	redirectURL := r.URL.Query().Get("redirect_url")
	// TODO: must be one of the registered mcp client routes

	if redirectURL == "" {
		http.Error(w, "missing redirect_url query parameter", http.StatusBadRequest)
		return
	}

	ctx := r.Context()

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

	requiresUpstreamOAuth2Token := srv.relyingParties.HasOAuth2ConfigForHost(r.Host)
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
		ClientId:    "internal-mcp-client",
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

	loginURL, ok := srv.relyingParties.GetLoginURLForHost(r.Host, authReqID)
	if ok {
		http.Redirect(w, r, loginURL, http.StatusFound)
		return
	}
	log.Ctx(ctx).Error().Msg("mcp/connect: must have login URL, this is a bug")
}
