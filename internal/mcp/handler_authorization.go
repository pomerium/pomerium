package mcp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/bufbuild/protovalidate-go"
	"github.com/go-jose/go-jose/v3/jwt"
	"golang.org/x/sync/errgroup"
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

	v, err := oauth21.ParseCodeGrantAuthorizeRequest(r)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to parse authorization request")
		oauth21.ErrorResponse(w, http.StatusBadRequest, oauth21.InvalidRequest)
		return
	}
	v.UserId = userID
	v.SessionId = sessionID
	if err := protovalidate.Validate(v); err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to validate authorization request")
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

	requiresUpstreamOAuth2Token := srv.relyingParties.HasOAuth2ConfigForHost(r.Host)
	var authReqID string
	var hasUpstreamOAuth2Token bool
	{
		eg, ctx := errgroup.WithContext(ctx)
		eg.Go(func() error {
			var err error
			authReqID, err = srv.storage.CreateAuthorizationRequest(ctx, v)
			if err != nil {
				return fmt.Errorf("failed to create authorization request: %w", err)
			}
			return nil
		})
		eg.Go(func() error {
			if !requiresUpstreamOAuth2Token {
				return nil
			}

			var err error
			token, err := srv.GetUpstreamOAuth2Token(ctx, r.Host, userID)
			if err != nil && status.Code(err) != codes.NotFound {
				return fmt.Errorf("failed to get upstream oauth2 token: %w", err)
			}
			hasUpstreamOAuth2Token = token != ""
			return nil
		})

		err := eg.Wait()
		if err != nil {
			log.Ctx(ctx).Error().Err(err).Msg("prepare for authorization redirect")
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	}

	if !requiresUpstreamOAuth2Token || hasUpstreamOAuth2Token {
		srv.AuthorizationResponse(ctx, w, r, authReqID, v)
		return
	}

	loginURL, ok := srv.relyingParties.GetLoginURLForHost(r.Host, authReqID)
	if ok {
		http.Redirect(w, r, loginURL, http.StatusFound)
	}
	log.Ctx(ctx).Error().Msg("authorize: must have login URL, this is a bug")
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
	if req.GetClientId() == InternalConnectClientID {
		err := srv.storage.DeleteAuthorizationRequest(ctx, id)
		if err != nil {
			log.Ctx(ctx).Error().Err(err).Str("id", id).Msg("failed to delete authorization request")
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, req.GetRedirectUri(), http.StatusFound)
		return
	}

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

func getClaimsFromRequest(r *http.Request) (map[string]any, error) {
	h := r.Header.Get(httputil.HeaderPomeriumJWTAssertion)
	if h == "" {
		return nil, fmt.Errorf("missing %s header", httputil.HeaderPomeriumJWTAssertion)
	}

	token, err := jwt.ParseSigned(h)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT: %w", err)
	}
	var m map[string]any
	err = token.UnsafeClaimsWithoutVerification(&m)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT claims: %w", err)
	}

	return m, nil
}

func getSessionIDFromClaims(claims map[string]any) (string, bool) {
	sessionID, ok := claims["sid"].(string)
	return sessionID, ok
}

func getUserIDFromClaims(claims map[string]any) (string, bool) {
	userID, ok := claims["sub"].(string)
	return userID, ok
}
