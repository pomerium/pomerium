package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/oauth21"
	oauth21proto "github.com/pomerium/pomerium/internal/oauth21/gen"
)

// Token handles the /token endpoint.
func (srv *Handler) Token(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	req, err := oauth21.ParseTokenRequest(r)
	if err != nil {
		log.Ctx(r.Context()).Error().Err(err).Msg("failed to parse token request")
		oauth21.ErrorResponse(w, http.StatusBadRequest, oauth21.InvalidRequest)
		return
	}

	switch req.GrantType {
	case "authorization_code":
		srv.handleAuthorizationCodeToken(w, r, req)
	default:
		oauth21.ErrorResponse(w, http.StatusBadRequest, oauth21.UnsupportedGrantType)
		return
	}
}

func (srv *Handler) handleAuthorizationCodeToken(w http.ResponseWriter, r *http.Request, req *oauth21proto.TokenRequest) {
	ctx := r.Context()

	if req.ClientId == nil {
		oauth21.ErrorResponse(w, http.StatusBadRequest, oauth21.InvalidClient)
		return
	}
	if req.Code == nil {
		oauth21.ErrorResponse(w, http.StatusBadRequest, oauth21.InvalidGrant)
		return
	}
	code, err := DecryptCode(CodeTypeAuthorization, *req.Code, srv.cipher, *req.ClientId, time.Now())
	if err != nil {
		oauth21.ErrorResponse(w, http.StatusBadRequest, oauth21.InvalidGrant)
		return
	}

	authReq, err := srv.storage.GetAuthorizationRequest(ctx, code.Id)
	if status.Code(err) == codes.NotFound {
		oauth21.ErrorResponse(w, http.StatusBadRequest, oauth21.InvalidGrant)
		return
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}

	if *req.ClientId != authReq.ClientId {
		oauth21.ErrorResponse(w, http.StatusBadRequest, oauth21.InvalidGrant)
	}

	err = CheckPKCE(authReq.GetCodeChallengeMethod(), authReq.GetCodeChallenge(), req.GetCodeVerifier())
	if err != nil {
		oauth21.ErrorResponse(w, http.StatusBadRequest, oauth21.InvalidGrant)
		return
	}

	// The authorization server MUST return an access token only once for a given authorization code.
	// https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-12#section-4.1.3
	err = srv.storage.DeleteAuthorizationRequest(ctx, code.Id)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	session, err := srv.storage.GetSession(ctx, authReq.SessionId)
	if status.Code(err) == codes.NotFound {
		oauth21.ErrorResponse(w, http.StatusBadRequest, oauth21.InvalidGrant)
		return
	}

	accessToken, err := CreateAccessToken(session, srv.cipher)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	expiresIn := time.Until(session.ExpiresAt.AsTime())
	if expiresIn < 0 {
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
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (srv *Handler) GetSessionIDFromAccessToken(ctx context.Context, accessToken string) (string, bool) {
	sessionID, err := DecryptAccessToken(accessToken, srv.cipher)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to decrypt access token")
		return "", false
	}
	return sessionID, true
}
