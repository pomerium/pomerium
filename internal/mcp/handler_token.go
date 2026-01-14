package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/oauth2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/oauth21"
	oauth21proto "github.com/pomerium/pomerium/internal/oauth21/gen"
	rfc7591v1 "github.com/pomerium/pomerium/internal/rfc7591"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/identity/identity"
	"github.com/pomerium/pomerium/pkg/identity/manager"
)

// noopState implements identity.State for refresh operations where we don't need the ID token claims.
// This is used in MCP refresh token flow where we only need the access token and refresh token
// from the upstream IdP - the ID token claims are not used.
// Must use pointer receiver so that Claims() can unmarshal into it.
type noopState struct{}

func (*noopState) SetRawIDToken(_ string) {}

const (
	// RefreshTokenTTL is the lifetime for MCP refresh tokens.
	// The actual validity depends on whether the upstream IdP token can still be refreshed.
	RefreshTokenTTL = 365 * 24 * time.Hour
)

// Token handles the /token endpoint.
func (srv *Handler) Token(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	log.Ctx(ctx).Debug().
		Str("method", r.Method).
		Str("host", r.Host).
		Str("path", r.URL.Path).
		Str("content-type", r.Header.Get("Content-Type")).
		Msg("mcp/token: request received")

	if r.Method != http.MethodPost {
		log.Ctx(ctx).Debug().Str("method", r.Method).Msg("mcp/token: rejecting non-POST method")
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	req, err := srv.getTokenRequest(r)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("mcp/token: get token request failed")
		oauth21.ErrorResponse(w, http.StatusBadRequest, oauth21.InvalidRequest)
		return
	}

	log.Ctx(ctx).Debug().
		Str("grant-type", req.GrantType).
		Str("client-id", req.GetClientId()).
		Bool("has-code", req.Code != nil).
		Bool("has-refresh-token", req.RefreshToken != nil).
		Bool("has-code-verifier", req.CodeVerifier != nil).
		Msg("mcp/token: parsed token request")

	switch req.GrantType {
	case "authorization_code":
		log.Ctx(ctx).Debug().Msg("mcp/token: handling authorization_code grant")
		srv.handleAuthorizationCodeToken(w, r, req)
	case "refresh_token":
		log.Ctx(ctx).Debug().Msg("mcp/token: handling refresh_token grant")
		srv.handleRefreshTokenGrant(w, r, req)
	default:
		log.Ctx(ctx).Error().Str("grant-type", req.GrantType).Msg("mcp/token: unsupported grant type")
		oauth21.ErrorResponse(w, http.StatusBadRequest, oauth21.UnsupportedGrantType)
		return
	}
}

func (srv *Handler) handleAuthorizationCodeToken(w http.ResponseWriter, r *http.Request, tokenReq *oauth21proto.TokenRequest) {
	ctx := r.Context()

	log.Ctx(ctx).Debug().
		Str("client-id", tokenReq.GetClientId()).
		Msg("mcp/token/auth-code: starting authorization code exchange")

	if tokenReq.ClientId == nil {
		log.Ctx(ctx).Error().Msg("mcp/token/auth-code: missing client_id in token request")
		oauth21.ErrorResponse(w, http.StatusBadRequest, oauth21.InvalidClient)
		return
	}
	if tokenReq.Code == nil {
		log.Ctx(ctx).Error().Msg("mcp/token/auth-code: missing code in token request")
		oauth21.ErrorResponse(w, http.StatusBadRequest, oauth21.InvalidGrant)
		return
	}

	log.Ctx(ctx).Debug().
		Int("code-length", len(*tokenReq.Code)).
		Msg("mcp/token/auth-code: decrypting authorization code")

	code, err := DecryptCode(CodeTypeAuthorization, *tokenReq.Code, srv.cipher, *tokenReq.ClientId, time.Now())
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("mcp/token/auth-code: failed to decrypt authorization code")
		oauth21.ErrorResponse(w, http.StatusBadRequest, oauth21.InvalidGrant)
		return
	}

	log.Ctx(ctx).Debug().
		Str("auth-req-id", code.Id).
		Time("code-expires", code.ExpiresAt.AsTime()).
		Msg("mcp/token/auth-code: authorization code decrypted, fetching authorization request")

	authReq, err := srv.storage.GetAuthorizationRequest(ctx, code.Id)
	if status.Code(err) == codes.NotFound {
		log.Ctx(ctx).Error().
			Str("auth-req-id", code.Id).
			Msg("mcp/token/auth-code: authorization request not found")
		oauth21.ErrorResponse(w, http.StatusBadRequest, oauth21.InvalidGrant)
		return
	}
	if err != nil {
		log.Ctx(ctx).Error().Err(err).
			Str("auth-req-id", code.Id).
			Msg("mcp/token/auth-code: failed to get authorization request")
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	log.Ctx(ctx).Debug().
		Str("auth-req-id", code.Id).
		Str("stored-client-id", authReq.ClientId).
		Str("stored-session-id", authReq.SessionId).
		Str("stored-user-id", authReq.UserId).
		Str("redirect-uri", authReq.GetRedirectUri()).
		Strs("scopes", authReq.GetScopes()).
		Msg("mcp/token/auth-code: retrieved authorization request from storage")

	if *tokenReq.ClientId != authReq.ClientId {
		log.Ctx(ctx).Error().
			Str("request-client-id", *tokenReq.ClientId).
			Str("stored-client-id", authReq.ClientId).
			Msg("mcp/token/auth-code: client ID mismatch")
		oauth21.ErrorResponse(w, http.StatusBadRequest, oauth21.InvalidGrant)
		return
	}

	log.Ctx(ctx).Debug().
		Str("code-challenge-method", authReq.GetCodeChallengeMethod()).
		Bool("has-code-challenge", authReq.GetCodeChallenge() != "").
		Bool("has-code-verifier", tokenReq.GetCodeVerifier() != "").
		Msg("mcp/token/auth-code: verifying PKCE")

	err = CheckPKCE(authReq.GetCodeChallengeMethod(), authReq.GetCodeChallenge(), tokenReq.GetCodeVerifier())
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("mcp/token/auth-code: PKCE verification failed")
		oauth21.ErrorResponse(w, http.StatusBadRequest, oauth21.InvalidGrant)
		return
	}

	log.Ctx(ctx).Debug().Msg("mcp/token/auth-code: PKCE verified, deleting authorization request (one-time use)")

	// The authorization server MUST return an access token only once for a given authorization code.
	// https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-12#section-4.1.3
	err = srv.storage.DeleteAuthorizationRequest(ctx, code.Id)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("mcp/token/auth-code: failed to delete authorization request")
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	log.Ctx(ctx).Debug().
		Str("session-id", authReq.SessionId).
		Str("user-id", authReq.UserId).
		Str("client-id", authReq.ClientId).
		Msg("mcp/token/auth-code: fetching session for token exchange")

	session, err := srv.storage.GetSession(ctx, authReq.SessionId)
	if status.Code(err) == codes.NotFound {
		log.Ctx(ctx).Error().
			Str("session-id", authReq.SessionId).
			Msg("mcp/token/auth-code: session not found")
		oauth21.ErrorResponse(w, http.StatusBadRequest, oauth21.InvalidGrant)
		return
	}
	if err != nil {
		log.Ctx(ctx).Error().Err(err).
			Str("session-id", authReq.SessionId).
			Msg("mcp/token/auth-code: failed to get session")
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	log.Ctx(ctx).Debug().
		Str("session-id", session.Id).
		Str("user-id", session.UserId).
		Str("idp-id", session.IdpId).
		Time("issued-at", session.IssuedAt.AsTime()).
		Time("expires-at", session.ExpiresAt.AsTime()).
		Bool("has-oauth-token", session.OauthToken != nil).
		Bool("has-upstream-refresh-token", session.GetOauthToken().GetRefreshToken() != "").
		Msg("mcp/token/auth-code: session found for token exchange")

	sessionExpiresAt := session.ExpiresAt.AsTime()
	if sessionExpiresAt.Before(time.Now()) {
		log.Ctx(ctx).Error().
			Time("session-expires-at", sessionExpiresAt).
			Time("now", time.Now()).
			Msg("mcp/token/auth-code: session has already expired")
		oauth21.ErrorResponse(w, http.StatusBadRequest, oauth21.InvalidGrant)
		return
	}

	// Create MCP refresh token record with upstream refresh token for session recreation
	refreshTokenRecord := &oauth21proto.MCPRefreshToken{
		Id:                   uuid.NewString(),
		UserId:               session.UserId,
		ClientId:             *tokenReq.ClientId,
		IdpId:                session.IdpId,
		UpstreamRefreshToken: session.GetOauthToken().GetRefreshToken(),
		IssuedAt:             timestamppb.Now(),
		ExpiresAt:            timestamppb.New(time.Now().Add(RefreshTokenTTL)),
		Scopes:               authReq.GetScopes(),
	}

	log.Ctx(ctx).Debug().
		Str("refresh-token-id", refreshTokenRecord.Id).
		Str("user-id", refreshTokenRecord.UserId).
		Str("client-id", refreshTokenRecord.ClientId).
		Str("idp-id", refreshTokenRecord.IdpId).
		Bool("has-upstream-refresh-token", refreshTokenRecord.UpstreamRefreshToken != "").
		Time("expires-at", refreshTokenRecord.ExpiresAt.AsTime()).
		Strs("scopes", refreshTokenRecord.Scopes).
		Msg("mcp/token/auth-code: storing MCP refresh token record")

	if err := srv.storage.PutMCPRefreshToken(ctx, refreshTokenRecord); err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("mcp/token/auth-code: failed to store MCP refresh token")
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	log.Ctx(ctx).Debug().
		Str("refresh-token-id", refreshTokenRecord.Id).
		Msg("mcp/token/auth-code: MCP refresh token stored, creating token response")

	resp, err := srv.createTokenResponse(session.Id, sessionExpiresAt, refreshTokenRecord, authReq.GetScopes())
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("mcp/token/auth-code: failed to create token response")
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	log.Ctx(ctx).Info().
		Str("client-id", *tokenReq.ClientId).
		Str("user-id", session.UserId).
		Str("session-id", session.Id).
		Str("refresh-token-id", refreshTokenRecord.Id).
		Int64("expires-in", resp.GetExpiresIn()).
		Str("scope", resp.GetScope()).
		Msg("mcp/token/auth-code: token issued successfully")

	writeTokenResponse(w, resp)
}

func (srv *Handler) getTokenRequest(
	r *http.Request,
) (*oauth21proto.TokenRequest, error) {
	ctx := r.Context()

	tokenReq, err := oauth21.ParseTokenRequest(r)
	if err != nil {
		return nil, fmt.Errorf("failed to parse token request: %w", err)
	}

	log.Ctx(ctx).Debug().
		Str("client-id", tokenReq.GetClientId()).
		Str("grant-type", tokenReq.GetGrantType()).
		Msg("mcp/token: fetching client for authentication")

	clientReg, err := srv.getOrFetchClient(ctx, tokenReq.GetClientId())
	if err != nil {
		log.Ctx(ctx).Debug().Err(err).Str("client-id", tokenReq.GetClientId()).Msg("mcp/token: failed to fetch client")
		return nil, fmt.Errorf("failed to get client registration: %w", err)
	}

	m := clientReg.ResponseMetadata.GetTokenEndpointAuthMethod()
	log.Ctx(ctx).Debug().
		Str("auth-method", m).
		Bool("has-client-secret", clientReg.ClientSecret != nil).
		Msg("mcp/token: checking token endpoint authentication method")

	if m == rfc7591v1.TokenEndpointAuthMethodNone {
		log.Ctx(ctx).Debug().Msg("mcp/token: no client authentication required")
		return tokenReq, nil
	}

	secret := clientReg.ClientSecret
	if secret == nil {
		return nil, fmt.Errorf("client registration does not have a client secret")
	}
	if expires := secret.ExpiresAt; expires != nil && expires.AsTime().Before(time.Now()) {
		log.Ctx(ctx).Debug().Time("secret-expires", expires.AsTime()).Msg("mcp/token: client secret has expired")
		return nil, fmt.Errorf("client registration client secret has expired")
	}

	switch m {
	case rfc7591v1.TokenEndpointAuthMethodClientSecretBasic:
		log.Ctx(ctx).Debug().Msg("mcp/token: client_secret_basic authentication (handled by HTTP layer)")
	case rfc7591v1.TokenEndpointAuthMethodClientSecretPost:
		log.Ctx(ctx).Debug().
			Bool("has-client-secret-in-request", tokenReq.ClientSecret != nil).
			Msg("mcp/token: verifying client_secret_post authentication")
		if tokenReq.ClientSecret == nil {
			return nil, fmt.Errorf("client_secret was not provided")
		}
		if tokenReq.GetClientSecret() != secret.Value {
			return nil, fmt.Errorf("client secret mismatch")
		}
		log.Ctx(ctx).Debug().Msg("mcp/token: client secret verified")
	default:
		return nil, fmt.Errorf("unsupported token endpoint authentication method: %s", m)
	}

	return tokenReq, nil
}

func (srv *Handler) handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request, tokenReq *oauth21proto.TokenRequest) {
	ctx := r.Context()

	log.Ctx(ctx).Debug().
		Str("client-id", tokenReq.GetClientId()).
		Msg("mcp/token/refresh: starting refresh token exchange")

	if tokenReq.ClientId == nil {
		log.Ctx(ctx).Error().Msg("mcp/token/refresh: missing client_id in refresh token request")
		oauth21.ErrorResponse(w, http.StatusBadRequest, oauth21.InvalidClient)
		return
	}
	if tokenReq.RefreshToken == nil {
		log.Ctx(ctx).Error().Msg("mcp/token/refresh: missing refresh_token in token request")
		oauth21.ErrorResponse(w, http.StatusBadRequest, oauth21.InvalidGrant)
		return
	}

	log.Ctx(ctx).Debug().
		Int("refresh-token-length", len(*tokenReq.RefreshToken)).
		Msg("mcp/token/refresh: decrypting refresh token")

	// Decrypt the refresh token to get the record ID
	refreshCode, err := srv.DecryptRefreshToken(*tokenReq.RefreshToken, *tokenReq.ClientId)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("mcp/token/refresh: failed to decrypt refresh token")
		oauth21.ErrorResponse(w, http.StatusBadRequest, oauth21.InvalidGrant)
		return
	}

	log.Ctx(ctx).Debug().
		Str("refresh-token-id", refreshCode.Id).
		Time("refresh-token-expires", refreshCode.ExpiresAt.AsTime()).
		Msg("mcp/token/refresh: refresh token decrypted, fetching stored record")

	// Get the stored refresh token record
	refreshTokenRecord, err := srv.storage.GetMCPRefreshToken(ctx, refreshCode.Id)
	if status.Code(err) == codes.NotFound {
		log.Ctx(ctx).Error().
			Str("refresh-token-id", refreshCode.Id).
			Msg("mcp/token/refresh: refresh token record not found")
		oauth21.ErrorResponse(w, http.StatusBadRequest, oauth21.InvalidGrant)
		return
	}
	if err != nil {
		log.Ctx(ctx).Error().Err(err).
			Str("refresh-token-id", refreshCode.Id).
			Msg("mcp/token/refresh: failed to get refresh token record")
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	log.Ctx(ctx).Debug().
		Str("refresh-token-id", refreshTokenRecord.Id).
		Str("stored-client-id", refreshTokenRecord.ClientId).
		Str("stored-user-id", refreshTokenRecord.UserId).
		Str("idp-id", refreshTokenRecord.IdpId).
		Bool("revoked", refreshTokenRecord.Revoked).
		Time("issued-at", refreshTokenRecord.IssuedAt.AsTime()).
		Time("expires-at", refreshTokenRecord.ExpiresAt.AsTime()).
		Bool("has-upstream-refresh-token", refreshTokenRecord.UpstreamRefreshToken != "").
		Strs("scopes", refreshTokenRecord.Scopes).
		Msg("mcp/token/refresh: retrieved refresh token record from storage")

	// Validate client ID matches
	if refreshTokenRecord.ClientId != *tokenReq.ClientId {
		log.Ctx(ctx).Error().
			Str("request-client-id", *tokenReq.ClientId).
			Str("stored-client-id", refreshTokenRecord.ClientId).
			Msg("mcp/token/refresh: client_id mismatch for refresh token")
		oauth21.ErrorResponse(w, http.StatusBadRequest, oauth21.InvalidGrant)
		return
	}

	// Check if refresh token is revoked
	if refreshTokenRecord.Revoked {
		log.Ctx(ctx).Error().
			Str("refresh-token-id", refreshTokenRecord.Id).
			Msg("mcp/token/refresh: refresh token has been revoked")
		oauth21.ErrorResponse(w, http.StatusBadRequest, oauth21.InvalidGrant)
		return
	}

	// Check refresh token expiration
	if refreshTokenRecord.ExpiresAt.AsTime().Before(time.Now()) {
		log.Ctx(ctx).Error().
			Str("refresh-token-id", refreshTokenRecord.Id).
			Time("expires-at", refreshTokenRecord.ExpiresAt.AsTime()).
			Time("now", time.Now()).
			Msg("mcp/token/refresh: refresh token has expired")
		oauth21.ErrorResponse(w, http.StatusBadRequest, oauth21.InvalidGrant)
		return
	}

	log.Ctx(ctx).Debug().
		Str("refresh-token-id", refreshTokenRecord.Id).
		Str("user-id", refreshTokenRecord.UserId).
		Msg("mcp/token/refresh: validation passed, getting or recreating session")

	// Try to get or recreate a valid session
	newSession, err := srv.getOrRecreateSession(ctx, refreshTokenRecord)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).
			Str("refresh-token-id", refreshTokenRecord.Id).
			Msg("mcp/token/refresh: failed to get or recreate session")
		oauth21.ErrorResponse(w, http.StatusBadRequest, oauth21.InvalidGrant)
		return
	}

	log.Ctx(ctx).Debug().
		Str("new-session-id", newSession.Id).
		Str("user-id", newSession.UserId).
		Time("expires-at", newSession.ExpiresAt.AsTime()).
		Bool("has-upstream-refresh-token", newSession.GetOauthToken().GetRefreshToken() != "").
		Msg("mcp/token/refresh: session obtained, proceeding with token rotation")

	// Update the refresh token record with the new session's upstream token (if rotated)
	if newSession.GetOauthToken().GetRefreshToken() != "" {
		log.Ctx(ctx).Debug().Msg("mcp/token/refresh: updating upstream refresh token from new session")
		refreshTokenRecord.UpstreamRefreshToken = newSession.GetOauthToken().GetRefreshToken()
	}

	// Create new refresh token record (rotation)
	newRefreshTokenRecord := &oauth21proto.MCPRefreshToken{
		Id:                   uuid.NewString(),
		UserId:               refreshTokenRecord.UserId,
		ClientId:             refreshTokenRecord.ClientId,
		IdpId:                refreshTokenRecord.IdpId,
		UpstreamRefreshToken: refreshTokenRecord.UpstreamRefreshToken,
		IssuedAt:             timestamppb.Now(),
		ExpiresAt:            timestamppb.New(time.Now().Add(RefreshTokenTTL)),
		Scopes:               refreshTokenRecord.Scopes,
	}

	log.Ctx(ctx).Debug().
		Str("old-refresh-token-id", refreshTokenRecord.Id).
		Str("new-refresh-token-id", newRefreshTokenRecord.Id).
		Time("new-expires-at", newRefreshTokenRecord.ExpiresAt.AsTime()).
		Msg("mcp/token/refresh: rotating refresh token (creating new, then revoking old)")

	// Store new refresh token first, then revoke old one.
	// This order ensures that if revoking fails, the user still has a valid token.
	if err := srv.storage.PutMCPRefreshToken(ctx, newRefreshTokenRecord); err != nil {
		log.Ctx(ctx).Error().Err(err).
			Str("refresh-token-id", newRefreshTokenRecord.Id).
			Msg("mcp/token/refresh: failed to store new refresh token")
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	log.Ctx(ctx).Debug().
		Str("refresh-token-id", newRefreshTokenRecord.Id).
		Msg("mcp/token/refresh: new refresh token stored")

	refreshTokenRecord.Revoked = true
	if err := srv.storage.PutMCPRefreshToken(ctx, refreshTokenRecord); err != nil {
		// Log the error but don't fail the request - the new token is already stored
		// and the user can continue. The old token will eventually expire.
		log.Ctx(ctx).Warn().Err(err).
			Str("refresh-token-id", refreshTokenRecord.Id).
			Msg("mcp/token/refresh: failed to revoke old refresh token (new token already issued)")
	} else {
		log.Ctx(ctx).Debug().
			Str("refresh-token-id", refreshTokenRecord.Id).
			Msg("mcp/token/refresh: old refresh token revoked")
	}

	sessionExpiresAt := newSession.ExpiresAt.AsTime()
	resp, err := srv.createTokenResponse(newSession.Id, sessionExpiresAt, newRefreshTokenRecord, refreshTokenRecord.Scopes)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("mcp/token/refresh: failed to create token response")
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	log.Ctx(ctx).Info().
		Str("client-id", refreshTokenRecord.ClientId).
		Str("user-id", refreshTokenRecord.UserId).
		Str("session-id", newSession.Id).
		Str("old-refresh-token-id", refreshTokenRecord.Id).
		Str("new-refresh-token-id", newRefreshTokenRecord.Id).
		Int64("expires-in", resp.GetExpiresIn()).
		Str("scope", resp.GetScope()).
		Msg("mcp/token/refresh: token refreshed successfully")

	writeTokenResponse(w, resp)
}

// getOrRecreateSession tries to get an existing valid session, or recreates it using the upstream refresh token.
func (srv *Handler) getOrRecreateSession(
	ctx context.Context,
	refreshTokenRecord *oauth21proto.MCPRefreshToken,
) (*session.Session, error) {
	log.Ctx(ctx).Debug().
		Str("user-id", refreshTokenRecord.UserId).
		Str("idp-id", refreshTokenRecord.IdpId).
		Bool("has-upstream-refresh-token", refreshTokenRecord.UpstreamRefreshToken != "").
		Msg("mcp/session: recreating session from refresh token")

	// For now, we need to create a new session since we don't track the original session ID
	// The session will be created using the upstream refresh token

	if refreshTokenRecord.UpstreamRefreshToken == "" {
		log.Ctx(ctx).Error().Msg("mcp/session: no upstream refresh token available")
		return nil, fmt.Errorf("no upstream refresh token available")
	}

	// Refresh the upstream token to get a fresh access token
	// This is necessary because the identity manager's updateUserInfo scheduler
	// will try to use the access token directly without refreshing first.
	var newOAuthToken *oauth2.Token
	if srv.getAuthenticator != nil {
		log.Ctx(ctx).Debug().
			Str("idp-id", refreshTokenRecord.IdpId).
			Msg("mcp/session: getting authenticator for upstream token refresh")

		authenticator, err := srv.getAuthenticator(ctx, refreshTokenRecord.IdpId)
		if err != nil {
			log.Ctx(ctx).Warn().Err(err).
				Str("idp-id", refreshTokenRecord.IdpId).
				Msg("mcp/session: failed to get authenticator for upstream token refresh, session will have no access token")
		} else if authenticator == nil {
			log.Ctx(ctx).Warn().
				Str("idp-id", refreshTokenRecord.IdpId).
				Msg("mcp/session: authenticator is nil, session will have no access token")
		} else {
			log.Ctx(ctx).Debug().Msg("mcp/session: refreshing upstream OAuth token")
			oldToken := &oauth2.Token{
				RefreshToken: refreshTokenRecord.UpstreamRefreshToken,
			}
			// Use noopState since we don't need the ID token claims in the MCP flow -
			// we only need the access token and refresh token from the upstream IdP.
			var state identity.State = &noopState{}
			newOAuthToken, err = authenticator.Refresh(ctx, oldToken, state)
			if err != nil {
				log.Ctx(ctx).Warn().Err(err).Msg("mcp/session: failed to refresh upstream token, session will have no access token")
			} else if newOAuthToken != nil {
				log.Ctx(ctx).Debug().
					Bool("has-access-token", newOAuthToken.AccessToken != "").
					Bool("has-new-refresh-token", newOAuthToken.RefreshToken != "").
					Time("expiry", newOAuthToken.Expiry).
					Msg("mcp/session: upstream token refreshed successfully")
			}
		}
	} else {
		log.Ctx(ctx).Debug().Msg("mcp/session: no authenticator getter configured, skipping upstream token refresh")
	}

	// Create a new session
	newSessionID := uuid.NewString()
	newSession := session.Create(refreshTokenRecord.IdpId, newSessionID, refreshTokenRecord.UserId, time.Now(), srv.sessionExpiry)

	log.Ctx(ctx).Debug().
		Str("session-id", newSession.Id).
		Str("user-id", newSession.UserId).
		Str("idp-id", newSession.IdpId).
		Time("expires-at", newSession.ExpiresAt.AsTime()).
		Bool("has-fresh-oauth-token", newOAuthToken != nil).
		Msg("mcp/session: created new session")

	if newOAuthToken != nil {
		newSession.OauthToken = manager.ToOAuthToken(newOAuthToken)
		log.Ctx(ctx).Debug().Msg("mcp/session: attached fresh OAuth token to session")
	} else {
		// Fallback: set refresh token only if we couldn't get a fresh access token
		newSession.OauthToken = &session.OAuthToken{
			RefreshToken: refreshTokenRecord.UpstreamRefreshToken,
		}
		log.Ctx(ctx).Debug().Msg("mcp/session: attached upstream refresh token only (no fresh access token)")
	}

	// Store the new session
	log.Ctx(ctx).Debug().
		Str("session-id", newSession.Id).
		Msg("mcp/session: storing new session in databroker")

	if err := srv.storage.PutSession(ctx, newSession); err != nil {
		log.Ctx(ctx).Error().Err(err).
			Str("session-id", newSession.Id).
			Msg("mcp/session: failed to store new session")
		return nil, fmt.Errorf("failed to store new session: %w", err)
	}

	log.Ctx(ctx).Debug().
		Str("session-id", newSession.Id).
		Msg("mcp/session: session stored successfully")

	return newSession, nil
}

// createTokenResponse generates access and refresh tokens for a session.
func (srv *Handler) createTokenResponse(
	sessionID string,
	sessionExpiresAt time.Time,
	refreshTokenRecord *oauth21proto.MCPRefreshToken,
	scopes []string,
) (*oauth21proto.TokenResponse, error) {
	accessToken, err := srv.GetAccessTokenForSession(sessionID, sessionExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("create access token: %w", err)
	}

	// Create encrypted refresh token that references the stored record
	refreshToken, err := srv.CreateRefreshToken(refreshTokenRecord.Id, refreshTokenRecord.ClientId, refreshTokenRecord.ExpiresAt.AsTime())
	if err != nil {
		return nil, fmt.Errorf("create refresh token: %w", err)
	}

	expiresIn := time.Until(sessionExpiresAt)

	resp := &oauth21proto.TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    proto.Int64(int64(expiresIn.Seconds())),
		RefreshToken: proto.String(refreshToken),
	}

	if len(scopes) > 0 {
		resp.Scope = proto.String(strings.Join(scopes, " "))
	}

	return resp, nil
}

// writeTokenResponse writes the token response to the HTTP response writer.
func writeTokenResponse(w http.ResponseWriter, resp *oauth21proto.TokenResponse) {
	// not using protojson.Marshal here because it emits numbers as strings,
	// which is valid, but for some reason Node.js / mcp typescript SDK doesn't like it
	data, err := json.Marshal(resp)
	if err != nil {
		log.Error().Err(err).Msg("mcp/token: failed to marshal token response")
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}
