package mcp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/oauth21"
	oauth21proto "github.com/pomerium/pomerium/internal/oauth21/gen"
	rfc7591v1 "github.com/pomerium/pomerium/internal/rfc7591"
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

	accessToken, err := srv.GetAccessTokenForSession(session.Id, session.ExpiresAt.AsTime())
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to get access token for session")
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	expiresIn := time.Until(session.ExpiresAt.AsTime())
	if expiresIn < 0 {
		log.Ctx(ctx).Error().Msg("session has already expired")
		oauth21.ErrorResponse(w, http.StatusBadRequest, oauth21.InvalidGrant)
		return
	}

	resp := &oauth21proto.TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   proto.Int64(int64(expiresIn.Seconds())),
	}

	data, err := json.Marshal(resp) // not using protojson.Marshal here because it emits numbers as strings, which is valid, but for some reason Node.js / mcp typescript SDK doesn't like it
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to marshal token response")
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (srv *Handler) getTokenRequest(
	r *http.Request,
) (*oauth21proto.TokenRequest, error) {
	tokenReq, err := oauth21.ParseTokenRequest(r)
	if err != nil {
		return nil, fmt.Errorf("failed to parse token request: %w", err)
	}

	ctx := r.Context()
	clientReg, err := srv.storage.GetClient(ctx, tokenReq.GetClientId())
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
