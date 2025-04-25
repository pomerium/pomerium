package mcp

import (
	"net/http"
	"time"

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
	if err != nil {
		oauth21.ErrorResponse(w, http.StatusBadRequest, oauth21.InvalidGrant)
		return
	}

	err = AuthorizeTokenRequest(req, authReq)
	if err != nil {
		oauth21.ErrorResponse(w, http.StatusBadRequest, oauth21.InvalidGrant)
		return
	}

	http.Error(w, "Not Implemented", http.StatusNotImplemented)
}
