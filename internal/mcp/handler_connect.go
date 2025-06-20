package mcp

import (
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

// Connect is a helper method for MCP clients to ensure that the current user
// has an active upstream Oauth2 session for the route.
// GET /mcp/connect?redirect_url=<url>
// It will redirect to the provided redirect_url once the user has an active session.
func (srv *Handler) Connect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "invalid method", http.StatusMethodNotAllowed)
		return
	}

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
