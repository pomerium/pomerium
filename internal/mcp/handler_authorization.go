package mcp

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/oauth21"
	oauth21proto "github.com/pomerium/pomerium/internal/oauth21/gen"
)

// Authorize handles the /authorize endpoint.
func (srv *Handler) Authorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "invalid method", http.StatusMethodNotAllowed)
		return
	}

	ctx := r.Context()

	v, err := oauth21.ParseCodeGrantAuthorizeRequest(r)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to parse authorization request")
		oauth21.ErrorResponse(w, http.StatusBadRequest, oauth21.InvalidRequest)
		return
	}

	client, err := srv.storage.GetClientByID(ctx, v.ClientId)
	if err != nil && status.Code(err) == codes.NotFound {
		log.Ctx(ctx).Error().Err(err).Str("id", v.ClientId).Msg("client id not found")
		oauth21.ErrorResponse(w, http.StatusUnauthorized, oauth21.InvalidClient)
		return
	}
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to get client")
		http.Error(w, "cannot fetch client", http.StatusInternalServerError)
		return
	}

	if err := oauth21.ValidateAuthorizationRequest(client, v); err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to validate authorization request")
		ve := oauth21.Error{Code: oauth21.InvalidRequest}
		_ = errors.As(err, &ve)
		oauth21.ErrorResponse(w, http.StatusBadRequest, ve.Code)
		return
	}

	id, err := srv.storage.CreateAuthorizationRequest(ctx, v)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to store authorization request")
		http.Error(w, "cannot create authorization request", http.StatusInternalServerError)
		return
	}

	srv.AuthorizationResponse(ctx, w, r, id, v)
}

// AuthorizationResponse generates the successful authorization response
// see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-12#section-4.1.2
func (srv *Handler) AuthorizationResponse(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	id string,
	req *oauth21proto.AuthorizationRequest,
) {
	code, err := CreateCode(
		id,
		time.Now().Add(time.Minute*10),
		req.ClientId,
		srv.cipher,
	)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to create code")
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	to, err := url.Parse(req.GetRedirectUri())
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to parse redirect uri")
		http.Error(w, "invalid redirect uri", http.StatusBadRequest)
		return
	}
	q := to.Query()
	q.Set("code", code)
	q.Set("state", req.GetState())
	to.RawQuery = q.Encode()
	http.Redirect(w, r, to.String(), http.StatusFound)
}
