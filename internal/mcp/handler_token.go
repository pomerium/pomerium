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
	"github.com/pomerium/pomerium/pkg/identity/manager"
)

const (
	// RefreshTokenTTL is the lifetime for MCP refresh tokens.
	// The actual validity depends on whether the upstream IdP token can still be refreshed.
	RefreshTokenTTL = 365 * 24 * time.Hour
)

// Token handles the /token endpoint.
func (srv *Handler) Token(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx := r.Context()
	req, err := srv.getTokenRequest(r)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("get token request failed")
		oauth21.ErrorResponse(w, http.StatusBadRequest, oauth21.InvalidRequest)
		return
	}

	switch req.GrantType {
	case "authorization_code":
		log.Ctx(ctx).Debug().Msg("handling authorization_code token request")
		srv.handleAuthorizationCodeToken(w, r, req)
	case "refresh_token":
		log.Ctx(ctx).Debug().Msg("handling refresh_token token request")
		srv.handleRefreshTokenGrant(w, r, req)
	default:
		log.Ctx(ctx).Error().Msgf("unsupported grant type: %s", req.GrantType)
		oauth21.ErrorResponse(w, http.StatusBadRequest, oauth21.UnsupportedGrantType)
		return
	}
}

func (srv *Handler) handleAuthorizationCodeToken(w http.ResponseWriter, r *http.Request, tokenReq *oauth21proto.TokenRequest) {
	ctx := r.Context()

	if tokenReq.ClientId == nil {
		log.Ctx(ctx).Error().Msg("missing client_id in token request")
		oauth21.ErrorResponse(w, http.StatusBadRequest, oauth21.InvalidClient)
		return
	}
	if tokenReq.Code == nil {
		log.Ctx(ctx).Error().Msg("missing code in token request")
		oauth21.ErrorResponse(w, http.StatusBadRequest, oauth21.InvalidGrant)
		return
	}
	code, err := DecryptCode(CodeTypeAuthorization, *tokenReq.Code, srv.cipher, *tokenReq.ClientId, time.Now())
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to decrypt authorization code")
		oauth21.ErrorResponse(w, http.StatusBadRequest, oauth21.InvalidGrant)
		return
	}

	authReq, err := srv.storage.GetAuthorizationRequest(ctx, code.Id)
	if status.Code(err) == codes.NotFound {
		log.Ctx(ctx).Error().Msg("authorization request not found")
		oauth21.ErrorResponse(w, http.StatusBadRequest, oauth21.InvalidGrant)
		return
	}
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to get authorization request and client")
		http.Error(w, "internal error", http.StatusInternalServerError)
	}

	if *tokenReq.ClientId != authReq.ClientId {
		log.Ctx(ctx).Error().Msgf("client ID mismatch: %s != %s", *tokenReq.ClientId, authReq.ClientId)
		oauth21.ErrorResponse(w, http.StatusBadRequest, oauth21.InvalidGrant)
		return
	}

	err = CheckPKCE(authReq.GetCodeChallengeMethod(), authReq.GetCodeChallenge(), tokenReq.GetCodeVerifier())
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to check PKCE")
		oauth21.ErrorResponse(w, http.StatusBadRequest, oauth21.InvalidGrant)
		return
	}

	// The authorization server MUST return an access token only once for a given authorization code.
	// https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-12#section-4.1.3
	err = srv.storage.DeleteAuthorizationRequest(ctx, code.Id)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to delete authorization request")
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	session, err := srv.storage.GetSession(ctx, authReq.SessionId)
	if status.Code(err) == codes.NotFound {
		log.Ctx(ctx).Error().Msg("session not found")
		oauth21.ErrorResponse(w, http.StatusBadRequest, oauth21.InvalidGrant)
		return
	}
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to get session")
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	sessionExpiresAt := session.ExpiresAt.AsTime()
	if sessionExpiresAt.Before(time.Now()) {
		log.Ctx(ctx).Error().Msg("session has already expired")
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

	if err := srv.storage.PutMCPRefreshToken(ctx, refreshTokenRecord); err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to store MCP refresh token")
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	resp, err := srv.createTokenResponse(session.Id, sessionExpiresAt, refreshTokenRecord, authReq.GetScopes())
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to create token response")
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	log.Ctx(ctx).Info().
		Str("client-id", *tokenReq.ClientId).
		Str("user-id", session.UserId).
		Str("session-id", session.Id).
		Msg("mcp token issued successfully")

	writeTokenResponse(w, resp)
}

func (srv *Handler) getTokenRequest(
	r *http.Request,
) (*oauth21proto.TokenRequest, error) {
	tokenReq, err := oauth21.ParseTokenRequest(r)
	if err != nil {
		return nil, fmt.Errorf("failed to parse token request: %w", err)
	}

	ctx := r.Context()
	log.Ctx(ctx).Debug().Str("client_id", tokenReq.GetClientId()).Msg("getTokenRequest: fetching client")
	clientReg, err := srv.getOrFetchClient(ctx, tokenReq.GetClientId())
	if err != nil {
		return nil, fmt.Errorf("failed to get client registration: %w", err)
	}

	m := clientReg.ResponseMetadata.GetTokenEndpointAuthMethod()
	if m == rfc7591v1.TokenEndpointAuthMethodNone {
		return tokenReq, nil
	}

	secret := clientReg.ClientSecret
	if secret == nil {
		return nil, fmt.Errorf("client registration does not have a client secret")
	}
	if expires := secret.ExpiresAt; expires != nil && expires.AsTime().Before(time.Now()) {
		return nil, fmt.Errorf("client registration client secret has expired")
	}

	switch m {
	case rfc7591v1.TokenEndpointAuthMethodClientSecretBasic:
	case rfc7591v1.TokenEndpointAuthMethodClientSecretPost:
		if tokenReq.ClientSecret == nil {
			return nil, fmt.Errorf("client_secret was not provided")
		}
		if tokenReq.GetClientSecret() != secret.Value {
			return nil, fmt.Errorf("client secret mismatch")
		}
	default:
		return nil, fmt.Errorf("unsupported token endpoint authentication method: %s", m)
	}

	return tokenReq, nil
}

func (srv *Handler) handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request, tokenReq *oauth21proto.TokenRequest) {
	ctx := r.Context()

	if tokenReq.ClientId == nil {
		log.Ctx(ctx).Error().Msg("missing client_id in refresh token request")
		oauth21.ErrorResponse(w, http.StatusBadRequest, oauth21.InvalidClient)
		return
	}
	if tokenReq.RefreshToken == nil {
		log.Ctx(ctx).Error().Msg("missing refresh_token in token request")
		oauth21.ErrorResponse(w, http.StatusBadRequest, oauth21.InvalidGrant)
		return
	}

	// Decrypt the refresh token to get the record ID
	refreshCode, err := srv.DecryptRefreshToken(*tokenReq.RefreshToken, *tokenReq.ClientId)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to decrypt refresh token")
		oauth21.ErrorResponse(w, http.StatusBadRequest, oauth21.InvalidGrant)
		return
	}

	// Get the stored refresh token record
	refreshTokenRecord, err := srv.storage.GetMCPRefreshToken(ctx, refreshCode.Id)
	if status.Code(err) == codes.NotFound {
		log.Ctx(ctx).Error().Msg("refresh token record not found")
		oauth21.ErrorResponse(w, http.StatusBadRequest, oauth21.InvalidGrant)
		return
	}
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to get refresh token record")
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Validate client ID matches
	if refreshTokenRecord.ClientId != *tokenReq.ClientId {
		log.Ctx(ctx).Error().Msg("client_id mismatch for refresh token")
		oauth21.ErrorResponse(w, http.StatusBadRequest, oauth21.InvalidGrant)
		return
	}

	// Check if refresh token is revoked
	if refreshTokenRecord.Revoked {
		log.Ctx(ctx).Error().Msg("refresh token has been revoked")
		oauth21.ErrorResponse(w, http.StatusBadRequest, oauth21.InvalidGrant)
		return
	}

	// Check refresh token expiration
	if refreshTokenRecord.ExpiresAt.AsTime().Before(time.Now()) {
		log.Ctx(ctx).Error().Msg("refresh token has expired")
		oauth21.ErrorResponse(w, http.StatusBadRequest, oauth21.InvalidGrant)
		return
	}

	// Try to get or recreate a valid session
	newSession, err := srv.getOrRecreateSession(ctx, refreshTokenRecord)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to get or recreate session")
		oauth21.ErrorResponse(w, http.StatusBadRequest, oauth21.InvalidGrant)
		return
	}

	// Update the refresh token record with the new session's upstream token (if rotated)
	if newSession.GetOauthToken().GetRefreshToken() != "" {
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

	// Revoke old refresh token and store new one
	refreshTokenRecord.Revoked = true
	if err := srv.storage.PutMCPRefreshToken(ctx, refreshTokenRecord); err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to revoke old refresh token")
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := srv.storage.PutMCPRefreshToken(ctx, newRefreshTokenRecord); err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to store new refresh token")
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	sessionExpiresAt := newSession.ExpiresAt.AsTime()
	resp, err := srv.createTokenResponse(newSession.Id, sessionExpiresAt, newRefreshTokenRecord, refreshTokenRecord.Scopes)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to create token response")
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	log.Ctx(ctx).Info().
		Str("client-id", refreshTokenRecord.ClientId).
		Str("user-id", refreshTokenRecord.UserId).
		Str("session-id", newSession.Id).
		Msg("mcp token refreshed successfully")

	writeTokenResponse(w, resp)
}

// getOrRecreateSession tries to get an existing valid session, or recreates it using the upstream refresh token.
func (srv *Handler) getOrRecreateSession(
	ctx context.Context,
	refreshTokenRecord *oauth21proto.MCPRefreshToken,
) (*session.Session, error) {
	// For now, we need to create a new session since we don't track the original session ID
	// The session will be created using the upstream refresh token

	if refreshTokenRecord.UpstreamRefreshToken == "" {
		return nil, fmt.Errorf("no upstream refresh token available")
	}

	// Refresh the upstream token to get a fresh access token
	// This is necessary because the identity manager's updateUserInfo scheduler
	// will try to use the access token directly without refreshing first.
	var newOAuthToken *oauth2.Token
	if srv.getAuthenticator != nil {
		authenticator, err := srv.getAuthenticator(ctx, refreshTokenRecord.IdpId)
		if err != nil {
			log.Ctx(ctx).Warn().Err(err).Msg("failed to get authenticator for upstream token refresh, session will have no access token")
		} else if authenticator == nil {
			log.Ctx(ctx).Warn().Msg("authenticator is nil, session will have no access token")
		} else {
			oldToken := &oauth2.Token{
				RefreshToken: refreshTokenRecord.UpstreamRefreshToken,
			}
			// Wrap Refresh in a recover since the authenticator may have missing configuration
			// (e.g., in test environments) that could cause a panic
			func() {
				defer func() {
					if r := recover(); r != nil {
						log.Ctx(ctx).Warn().Interface("panic", r).Msg("panic during upstream token refresh, session will have no access token")
					}
				}()
				newOAuthToken, err = authenticator.Refresh(ctx, oldToken, nil)
			}()
			if err != nil {
				log.Ctx(ctx).Warn().Err(err).Msg("failed to refresh upstream token, session will have no access token")
			}
		}
	}

	// Create a new session
	newSession := session.Create(refreshTokenRecord.IdpId, uuid.NewString(), refreshTokenRecord.UserId, time.Now(), 14*24*time.Hour) // 14 days default
	if newOAuthToken != nil {
		newSession.OauthToken = manager.ToOAuthToken(newOAuthToken)
	} else {
		// Fallback: set refresh token only if we couldn't get a fresh access token
		newSession.OauthToken = &session.OAuthToken{
			RefreshToken: refreshTokenRecord.UpstreamRefreshToken,
		}
	}

	// Store the new session
	if err := srv.storage.PutSession(ctx, newSession); err != nil {
		return nil, fmt.Errorf("failed to store new session: %w", err)
	}

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
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}
