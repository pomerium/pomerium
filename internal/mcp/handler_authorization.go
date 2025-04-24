package mcp

import (
	"errors"
	"net/http"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/oauth21"
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

	_, err = srv.storage.CreateAuthorizationRequest(ctx, v)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to store authorization request")
		http.Error(w, "cannot create authorization request", http.StatusInternalServerError)
		return
	}

	http.Error(w, "not implemented", http.StatusNotImplemented)
}
