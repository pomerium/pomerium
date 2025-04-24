package mcp

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/go-jose/go-jose/v3/jwt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/pomerium/pomerium/internal/httputil"
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

	sessionID, err := getSessionFromRequest(r)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("session is not present, this is a misconfigured request")
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	v, err := oauth21.ParseCodeGrantAuthorizeRequest(r, sessionID)
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

func getSessionFromRequest(r *http.Request) (string, error) {
	h := r.Header.Get(httputil.HeaderPomeriumJWTAssertion)
	if h == "" {
		return "", fmt.Errorf("missing %s header", httputil.HeaderPomeriumJWTAssertion)
	}

	token, err := jwt.ParseSigned(h)
	if err != nil {
		return "", fmt.Errorf("failed to parse JWT: %w", err)
	}
	var m map[string]any
	_ = token.UnsafeClaimsWithoutVerification(&m)
	sessionID, ok := m["sid"].(string)
	if !ok {
		return "", fmt.Errorf("missing session ID in JWT")
	}

	return sessionID, nil
}
