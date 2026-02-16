package mcp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"buf.build/go/protovalidate"
	"github.com/go-jose/go-jose/v3/jwt"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/oauth21"
	oauth21proto "github.com/pomerium/pomerium/internal/oauth21/gen"
	rfc7591v1 "github.com/pomerium/pomerium/internal/rfc7591"
)

// Authorize handles the /authorize endpoint.
func (srv *Handler) Authorize(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	log.Ctx(ctx).Debug().
		Str("method", r.Method).
		Str("host", r.Host).
		Str("path", r.URL.Path).
		Str("query", r.URL.RawQuery).
		Msg("mcp/authorize: request received")

	if r.Method != http.MethodGet {
		log.Ctx(ctx).Debug().Str("method", r.Method).Msg("mcp/authorize: rejecting non-GET method")
		http.Error(w, "invalid method", http.StatusMethodNotAllowed)
		return
	}

	claims, err := getClaimsFromRequest(r)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("mcp/authorize: failed to get claims from request")
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	log.Ctx(ctx).Debug().
		Interface("claims", claims).
		Msg("mcp/authorize: extracted JWT claims")

	sessionID, ok := getSessionIDFromClaims(claims)
	if !ok {
		log.Ctx(ctx).Error().
			Interface("claims", claims).
			Msg("mcp/authorize: session is not present in claims, this is a misconfigured request")
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	userID, ok := getUserIDFromClaims(claims)
	if !ok {
		log.Ctx(ctx).Error().
			Interface("claims", claims).
			Msg("mcp/authorize: user id is not present in claims, this is a misconfigured request")
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	v, err := oauth21.ParseCodeGrantAuthorizeRequest(r)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("mcp/authorize: failed to parse authorization request")
		oauth21.ErrorResponse(w, http.StatusBadRequest, oauth21.InvalidRequest)
		return
	}
	v.UserId = userID
	v.SessionId = sessionID

	log.Ctx(ctx).Debug().
		Str("session-id", sessionID).
		Str("user-id", userID).
		Str("client-id", v.ClientId).
		Str("redirect-uri", v.GetRedirectUri()).
		Str("state", v.GetState()).
		Str("code-challenge", v.GetCodeChallenge()).
		Str("code-challenge-method", v.GetCodeChallengeMethod()).
		Strs("scopes", v.GetScopes()).
		Msg("mcp/authorize: parsed authorization request")

	if err := protovalidate.Validate(v); err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("mcp/authorize: failed to validate authorization request")
		oauth21.ErrorResponse(w, http.StatusBadRequest, oauth21.InvalidRequest)
		return
	}

	log.Ctx(ctx).Debug().Str("client-id", v.ClientId).Msg("mcp/authorize: fetching client registration")
	client, err := srv.getOrFetchClient(ctx, v.ClientId)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Str("client-id", v.ClientId).Msg("mcp/authorize: failed to get client")

		if errors.Is(err, ErrDomainNotAllowed) {
			log.Ctx(ctx).Debug().Msg("mcp/authorize: responding with domain not allowed error page")
			domain := v.ClientId
			if u, parseErr := url.Parse(v.ClientId); parseErr == nil {
				domain = u.Hostname()
			}
			httputil.NewError(http.StatusUnauthorized, err).
				WithDescription(fmt.Sprintf(
					"The MCP client domain `%s` is not authorized. "+
						"Contact your Pomerium administrator to add this domain to the `mcp_allowed_client_id_domains` configuration option.",
					domain,
				)).
				ErrorResponse(ctx, w, r)
			return
		}

		if errors.Is(err, ErrClientMetadataValidation) || errors.Is(err, ErrClientMetadataFetch) {
			log.Ctx(ctx).Debug().Msg("mcp/authorize: responding with invalid_client (metadata error)")
			oauth21.ErrorResponse(w, http.StatusBadRequest, oauth21.InvalidClient)
		} else if status.Code(err) == codes.NotFound {
			log.Ctx(ctx).Debug().Msg("mcp/authorize: responding with invalid_client (not found)")
			oauth21.ErrorResponse(w, http.StatusUnauthorized, oauth21.InvalidClient)
		} else {
			log.Ctx(ctx).Debug().Msg("mcp/authorize: responding with internal error")
			http.Error(w, "cannot fetch client", http.StatusInternalServerError)
		}
		return
	}

	log.Ctx(ctx).Debug().
		Str("client-id", v.ClientId).
		Strs("redirect-uris", client.ResponseMetadata.GetRedirectUris()).
		Str("token-endpoint-auth-method", client.ResponseMetadata.GetTokenEndpointAuthMethod()).
		Msg("mcp/authorize: client registration found")

	if err := oauth21.ValidateAuthorizationRequest(client.ResponseMetadata, v); err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("mcp/authorize: failed to validate authorization request for client")
		ve := oauth21.Error{Code: oauth21.InvalidRequest}
		_ = errors.As(err, &ve)
		oauth21.ErrorResponse(w, http.StatusBadRequest, ve.Code)
		return
	}

	requiresUpstreamOAuth2Token := srv.hosts.HasOAuth2ConfigForHost(r.Host)
	log.Ctx(ctx).Debug().
		Str("host", r.Host).
		Bool("requires-upstream-oauth2", requiresUpstreamOAuth2Token).
		Msg("mcp/authorize: checking upstream OAuth2 requirement")

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
			log.Ctx(ctx).Debug().
				Str("auth-req-id", authReqID).
				Msg("mcp/authorize: created authorization request in storage")
			return nil
		})
		eg.Go(func() error {
			if !requiresUpstreamOAuth2Token {
				log.Ctx(ctx).Debug().Msg("mcp/authorize: no upstream OAuth2 required, skipping token check")
				return nil
			}

			var err error
			token, err := srv.GetUpstreamOAuth2Token(ctx, r.Host, userID)
			if err != nil && status.Code(err) != codes.NotFound {
				return fmt.Errorf("failed to get upstream oauth2 token: %w", err)
			}
			hasUpstreamOAuth2Token = token != ""
			log.Ctx(ctx).Debug().
				Bool("has-upstream-token", hasUpstreamOAuth2Token).
				Str("user-id", userID).
				Str("host", r.Host).
				Msg("mcp/authorize: checked upstream OAuth2 token")
			return nil
		})

		err := eg.Wait()
		if err != nil {
			log.Ctx(ctx).Error().Err(err).Msg("mcp/authorize: failed to prepare for authorization redirect")
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	}

	log.Ctx(ctx).Debug().
		Bool("requires-upstream", requiresUpstreamOAuth2Token).
		Bool("has-upstream-token", hasUpstreamOAuth2Token).
		Str("auth-req-id", authReqID).
		Msg("mcp/authorize: making redirect decision")

	// Auto-discovery upstream OAuth flow (single round-trip).
	// For routes without static upstream_oauth2 config, we proactively check if the upstream
	// requires OAuth by fetching its Protected Resource Metadata (PRM).
	hostname := stripPort(r.Host)
	if srv.hosts.UsesAutoDiscovery(hostname) {
		info, _ := srv.hosts.GetServerHostInfo(hostname)

		// Step 1: Check existing upstream token — skip discovery if we already have a valid one.
		if info.RouteID != "" && info.UpstreamURL != "" {
			token, tokenErr := srv.storage.GetUpstreamMCPToken(ctx, userID, info.RouteID, info.UpstreamURL)
			if tokenErr == nil && token != nil && (token.ExpiresAt == nil || token.ExpiresAt.AsTime().After(time.Now())) {
				log.Ctx(ctx).Debug().
					Str("user_id", userID).
					Str("route_id", info.RouteID).
					Msg("mcp/authorize: user has valid upstream token, issuing auth code directly")
				srv.AuthorizationResponse(ctx, w, r, authReqID, v)
				return
			}
		}

		// Step 2: Resolve upstream auth via pending state or proactive discovery.
		authURL, resolveErr := srv.resolveAutoDiscoveryAuth(ctx, &autoDiscoveryAuthParams{
			Hostname:  hostname,
			Host:      r.Host,
			UserID:    userID,
			AuthReqID: authReqID,
			Info:      info,
		})
		if resolveErr != nil {
			log.Ctx(ctx).Error().Err(resolveErr).Msg("mcp/authorize: failed to resolve auto-discovery auth")
			_ = srv.storage.DeleteAuthorizationRequest(ctx, authReqID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if authURL != "" {
			http.Redirect(w, r, authURL, http.StatusFound)
			return
		}
		// No PRM found — fall through to issue auth code.
		// ext_proc will catch if upstream actually returns 401 later.
	}

	if !requiresUpstreamOAuth2Token || hasUpstreamOAuth2Token {
		log.Ctx(ctx).Debug().Msg("mcp/authorize: proceeding to authorization response (no upstream login needed)")
		srv.AuthorizationResponse(ctx, w, r, authReqID, v)
		return
	}

	loginURL, ok := srv.hosts.GetLoginURLForHost(r.Host, authReqID)
	if ok {
		log.Ctx(ctx).Debug().
			Str("login-url", loginURL).
			Msg("mcp/authorize: redirecting to upstream OAuth2 login")
		http.Redirect(w, r, loginURL, http.StatusFound)
		return
	}
	log.Ctx(ctx).Error().Str("host", r.Host).Msg("mcp/authorize: must have login URL, this is a bug")
	http.Error(w, "internal error", http.StatusInternalServerError)
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
	log.Ctx(ctx).Debug().
		Str("auth-req-id", id).
		Str("client-id", req.GetClientId()).
		Str("redirect-uri", req.GetRedirectUri()).
		Str("session-id", req.GetSessionId()).
		Str("user-id", req.GetUserId()).
		Msg("mcp/authorize-response: generating authorization response")

	if req.GetClientId() == InternalConnectClientID {
		log.Ctx(ctx).Debug().
			Str("redirect-uri", req.GetRedirectUri()).
			Msg("mcp/authorize-response: internal connect client, redirecting directly")
		err := srv.storage.DeleteAuthorizationRequest(ctx, id)
		if err != nil {
			log.Ctx(ctx).Error().Err(err).Str("id", id).Msg("mcp/authorize-response: failed to delete authorization request")
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
		log.Ctx(ctx).Error().Err(err).Msg("mcp/authorize-response: failed to create code")
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	log.Ctx(ctx).Debug().
		Str("auth-req-id", id).
		Int("code-length", len(code)).
		Msg("mcp/authorize-response: created authorization code")

	to, err := url.Parse(req.GetRedirectUri())
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("mcp/authorize-response: failed to parse redirect uri")
		http.Error(w, "invalid redirect uri", http.StatusBadRequest)
		return
	}
	q := to.Query()
	q.Set("code", code)
	q.Set("state", req.GetState())
	to.RawQuery = q.Encode()

	log.Ctx(ctx).Debug().
		Str("redirect-url", to.String()).
		Str("state", req.GetState()).
		Msg("mcp/authorize-response: redirecting to client with authorization code")

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

// getOrFetchClient retrieves client registration either from storage (for dynamically registered clients)
// or by fetching and validating a client metadata document (for URL-based client IDs).
func (srv *Handler) getOrFetchClient(ctx context.Context, clientID string) (*rfc7591v1.ClientRegistration, error) {
	isMetadataURL, err := IsClientIDMetadataURL(clientID)
	if err != nil {
		return nil, err // Invalid URL format per RFC requirements
	}
	if isMetadataURL {
		doc, err := srv.clientMetadataFetcher.Fetch(ctx, clientID)
		if err != nil {
			return nil, err
		}
		return doc.ToClientRegistration(), nil
	}

	return srv.storage.GetClient(ctx, clientID)
}
