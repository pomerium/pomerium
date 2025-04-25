package mcp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/go-jose/go-jose/v3/jwt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/pomerium/pomerium/internal/httputil"
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

	client, err := srv.storage.GetClient(ctx, v.ClientId)
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
		CodeTypeAuthorization,
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
