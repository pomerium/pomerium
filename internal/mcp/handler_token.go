package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/oauth21"
	oauth21proto "github.com/pomerium/pomerium/internal/oauth21/gen"
	"github.com/pomerium/pomerium/internal/opaquetoken"
	rfc7591v1 "github.com/pomerium/pomerium/internal/rfc7591"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/idpsession"
	"github.com/pomerium/pomerium/pkg/grpc/session"
)

const (
	// RefreshTokenTTL is the lifetime of an MCP refresh token, and therefore of
	// the MCP client session it references. The identity manager deletes a
	// session once it expires and then revokes its binding, so the session has
	// to outlive every refresh token minted against it; each refresh re-issues
	// the session and slides its expiry by this much. Whether a refresh actually
	// succeeds depends on the user's upstream IdP session still being valid.
	RefreshTokenTTL = 365 * 24 * time.Hour
)

// errInvalidGrant marks a token request that must be answered with the OAuth
// invalid_grant error: the presented code or refresh token is well-formed but
// refers to a client session that can no longer be honored.
var errInvalidGrant = errors.New("invalid grant")

// Token handles the /token endpoint.
func (srv *Handler) Token(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	log.Ctx(ctx).Debug().
		Str("method", r.Method).
		Str("host", r.Host).
		Str("path", r.URL.Path).
		Str("content-type", r.Header.Get("Content-Type")).
		Msg("mcp/token: request received")

	if r.Method != http.MethodPost {
		log.Ctx(ctx).Debug().Str("method", r.Method).Msg("mcp/token: rejecting non-POST method")
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	req, err := srv.getTokenRequest(r)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("mcp/token: get token request failed")
		oauth21.ErrorResponse(w, http.StatusBadRequest, oauth21.InvalidRequest)
		return
	}

	log.Ctx(ctx).Debug().
		Str("grant-type", req.GrantType).
		Str("client-id", req.GetClientId()).
		Bool("has-code", req.Code != nil).
		Bool("has-refresh-token", req.RefreshToken != nil).
		Bool("has-code-verifier", req.CodeVerifier != nil).
		Msg("mcp/token: parsed token request")

	switch req.GrantType {
	case "authorization_code":
		srv.handleAuthorizationCodeToken(w, r, req)
	case "refresh_token":
		srv.handleRefreshTokenGrant(w, r, req)
	default:
		log.Ctx(ctx).Error().Str("grant-type", req.GrantType).Msg("mcp/token: unsupported grant type")
		oauth21.ErrorResponse(w, http.StatusBadRequest, oauth21.UnsupportedGrantType)
		return
	}
}

func (srv *Handler) handleAuthorizationCodeToken(w http.ResponseWriter, r *http.Request, tokenReq *oauth21proto.TokenRequest) {
	ctx := r.Context()

	if tokenReq.ClientId == nil {
		log.Ctx(ctx).Error().Msg("mcp/token/auth-code: missing client_id in token request")
		oauth21.ErrorResponse(w, http.StatusBadRequest, oauth21.InvalidClient)
		return
	}
	if tokenReq.Code == nil {
		log.Ctx(ctx).Error().Msg("mcp/token/auth-code: missing code in token request")
		oauth21.ErrorResponse(w, http.StatusBadRequest, oauth21.InvalidGrant)
		return
	}
	clientID := tokenReq.GetClientId()

	code, err := opaquetoken.Open(opaquetoken.TypeAuthorization, *tokenReq.Code, srv.cipher, clientID, time.Now())
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("mcp/token/auth-code: failed to decrypt authorization code")
		oauth21.ErrorResponse(w, http.StatusBadRequest, oauth21.InvalidGrant)
		return
	}

	authReq, err := srv.storage.GetAuthorizationRequest(ctx, code.Id)
	if status.Code(err) == codes.NotFound {
		log.Ctx(ctx).Error().Str("auth-req-id", code.Id).Msg("mcp/token/auth-code: authorization request not found")
		oauth21.ErrorResponse(w, http.StatusBadRequest, oauth21.InvalidGrant)
		return
	}
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Str("auth-req-id", code.Id).Msg("mcp/token/auth-code: failed to get authorization request")
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if clientID != authReq.ClientId {
		log.Ctx(ctx).Error().
			Str("request-client-id", clientID).
			Str("stored-client-id", authReq.ClientId).
			Msg("mcp/token/auth-code: client ID mismatch")
		oauth21.ErrorResponse(w, http.StatusBadRequest, oauth21.InvalidGrant)
		return
	}

	err = CheckPKCE(authReq.GetCodeChallengeMethod(), authReq.GetCodeChallenge(), tokenReq.GetCodeVerifier())
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("mcp/token/auth-code: PKCE verification failed")
		oauth21.ErrorResponse(w, http.StatusBadRequest, oauth21.InvalidGrant)
		return
	}

	// The authorization server MUST return an access token only once for a given authorization code.
	// https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-12#section-4.1.3
	err = srv.storage.DeleteAuthorizationRequest(ctx, code.Id)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("mcp/token/auth-code: failed to delete authorization request")
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// The MCP client becomes a dependent of the user's centralized IdP session,
	// like a browser session: its own session.Session, bound to the
	// IDPSession by a Binding the user can revoke. The initiating browser session
	// is not consulted; the user id recorded at /authorize is the IDPSession's id.
	idpSess, err := srv.resolveIDPSession(ctx, authReq.GetUserId())
	if err != nil {
		srv.writeGrantError(ctx, w, err, "mcp/token/auth-code: cannot issue for this user")
		return
	}

	now := time.Now()
	sess := newMCPSession(uuid.NewString(), idpSess, now)
	version, err := srv.storage.PutBoundSession(ctx, sess, map[string]string{
		"mcp_client_id": clientID,
		"client-ip":     httputil.GetClientIP(r),
	})
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("mcp/token/auth-code: failed to store mcp client session")
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	resp, err := srv.createTokenResponse(sess, version, clientID, now, authReq.GetScopes())
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("mcp/token/auth-code: failed to create token response")
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	log.Ctx(ctx).Info().
		Str("client-id", clientID).
		Str("user-id", sess.GetUserId()).
		Str("session-id", sess.GetId()).
		Int64("expires-in", resp.GetExpiresIn()).
		Str("scope", resp.GetScope()).
		Msg("mcp/token/auth-code: token issued successfully")

	writeTokenResponse(w, resp)
}

func (srv *Handler) getTokenRequest(
	r *http.Request,
) (*oauth21proto.TokenRequest, error) {
	ctx := r.Context()

	tokenReq, err := oauth21.ParseTokenRequest(r)
	if err != nil {
		return nil, fmt.Errorf("failed to parse token request: %w", err)
	}

	clientReg, err := srv.getOrFetchClient(ctx, tokenReq.GetClientId())
	if err != nil {
		log.Ctx(ctx).Debug().Err(err).Str("client-id", tokenReq.GetClientId()).Msg("mcp/token: failed to fetch client")
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
		// handled by the HTTP layer
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
		log.Ctx(ctx).Error().Msg("mcp/token/refresh: missing client_id in refresh token request")
		oauth21.ErrorResponse(w, http.StatusBadRequest, oauth21.InvalidClient)
		return
	}
	if tokenReq.RefreshToken == nil {
		log.Ctx(ctx).Error().Msg("mcp/token/refresh: missing refresh_token in token request")
		oauth21.ErrorResponse(w, http.StatusBadRequest, oauth21.InvalidGrant)
		return
	}
	clientID := tokenReq.GetClientId()

	// The client id is the token's AEAD associated data, so a refresh token
	// presented by a different client fails to open.
	payload, err := srv.DecryptRefreshToken(*tokenReq.RefreshToken, clientID)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("mcp/token/refresh: failed to decrypt refresh token")
		oauth21.ErrorResponse(w, http.StatusBadRequest, oauth21.InvalidGrant)
		return
	}

	now := time.Now()
	sess, version, err := srv.refreshMCPSession(ctx, payload, now)
	if err != nil {
		srv.writeGrantError(ctx, w, err, "mcp/token/refresh: cannot refresh mcp client session")
		return
	}

	// The refresh response omits scope: it is unchanged from the grant (RFC 6749 §5.1).
	resp, err := srv.createTokenResponse(sess, version, clientID, now, nil)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("mcp/token/refresh: failed to create token response")
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	log.Ctx(ctx).Info().
		Str("client-id", clientID).
		Str("user-id", sess.GetUserId()).
		Str("session-id", sess.GetId()).
		Int64("expires-in", resp.GetExpiresIn()).
		Msg("mcp/token/refresh: token refreshed successfully")

	writeTokenResponse(w, resp)
}

// refreshMCPSession re-issues the MCP client session a refresh token refers to.
//
// The refresh token is bound to the session's Binding: revoking the binding (from
// the user's session page, or by the identity manager when the IdP session dies)
// stops refresh at the first check, and the binding is never rewritten here. The
// session record is then re-issued from the IDPSession with a new issued_at,
// which is what rotates the refresh token: a token still carrying the previous
// issued_at is a replayed old generation and is refused. The re-issue is
// conditional on the session version read here, so of several concurrent
// presentations of one refresh token exactly one rotates the session; the
// others find it already consumed.
func (srv *Handler) refreshMCPSession(ctx context.Context, payload *opaquetoken.Payload, now time.Time) (*session.Session, uint64, error) {
	sessionID := payload.GetId()

	binding, err := srv.storage.GetActiveBinding(ctx, sessionID)
	if status.Code(err) == codes.NotFound {
		return nil, 0, fmt.Errorf("%w: no active binding for session %q: %w", errInvalidGrant, sessionID, err)
	} else if err != nil {
		return nil, 0, fmt.Errorf("get binding: %w", err)
	}

	idpSess, err := srv.resolveIDPSession(ctx, binding.GetIdpSessionId())
	if err != nil {
		return nil, 0, err
	}

	sess, version, err := srv.storage.GetSession(ctx, sessionID)
	if status.Code(err) == codes.NotFound {
		// The identity manager deletes expired sessions and then revokes their
		// binding; a session that is already gone means the grant expired.
		return nil, 0, fmt.Errorf("%w: session %q no longer exists", errInvalidGrant, sessionID)
	} else if err != nil {
		return nil, 0, fmt.Errorf("get session: %w", err)
	}
	if !payload.GetIssuedAt().AsTime().Equal(sess.GetIssuedAt().AsTime()) {
		return nil, 0, fmt.Errorf("%w: refresh token for session %q was rotated", errInvalidGrant, sessionID)
	}

	sess = newMCPSession(sessionID, idpSess, now)
	version, err = srv.storage.PutSession(ctx, sess, version)
	if databroker.IsRecordVersionMismatch(err) {
		return nil, 0, fmt.Errorf("%w: refresh token for session %q was consumed by a concurrent request", errInvalidGrant, sessionID)
	} else if err != nil {
		return nil, 0, fmt.Errorf("store mcp client session: %w", err)
	}
	return sess, version, nil
}

// resolveIDPSession loads a user's centralized IdP session. A missing or
// invalidated one wraps errInvalidGrant: the user signed out or the provider
// revoked them, so no MCP credential may be issued on their behalf.
func (srv *Handler) resolveIDPSession(ctx context.Context, id string) (*idpsession.IDPSession, error) {
	idpSess, err := srv.storage.GetValidIDPSession(ctx, id)
	if status.Code(err) == codes.NotFound {
		return nil, fmt.Errorf("%w: no valid centralized idp session for user %q: %w", errInvalidGrant, id, err)
	} else if err != nil {
		return nil, fmt.Errorf("get idp session: %w", err)
	}
	return idpSess, nil
}

// writeGrantError answers an errInvalidGrant with the OAuth invalid_grant error
// and anything else with a plain 500.
func (srv *Handler) writeGrantError(ctx context.Context, w http.ResponseWriter, err error, msg string) {
	if errors.Is(err, errInvalidGrant) {
		log.Ctx(ctx).Info().Err(err).Msg(msg)
		oauth21.ErrorResponse(w, http.StatusBadRequest, oauth21.InvalidGrant)
		return
	}
	log.Ctx(ctx).Error().Err(err).Msg(msg)
	http.Error(w, "internal error", http.StatusInternalServerError)
}

// newMCPSession issues an MCP client's session from the user's IDPSession. It
// carries the user's identity and upstream tokens like a browser session, and
// the identity manager keeps those fresh for as long as the session is bound.
//
// Its lifetime is the grant's (RefreshTokenTTL), not an access token's: the
// identity manager deletes expired sessions and then revokes their binding, so
// the session must outlive every refresh token minted against it. The access
// token carries its own, shorter expiry.
//
// refresh_disabled is deliberately left unset, as for browser sessions: the
// legacy per-session refresher is not wired, and with the flag set the identity
// manager would delete the session whenever the copied upstream access token
// expired before the next propagation.
func newMCPSession(id string, idpSess *idpsession.IDPSession, now time.Time) *session.Session {
	return idpsession.IssueSession(id, idpSess, now, RefreshTokenTTL)
}

// createTokenResponse mints the access and refresh tokens for a just-issued MCP
// client session.
func (srv *Handler) createTokenResponse(
	sess *session.Session,
	sessionRecordVersion uint64,
	clientID string,
	now time.Time,
	scopes []string,
) (*oauth21proto.TokenResponse, error) {
	accessToken, err := srv.GetAccessTokenForSessionWithVersion(sess.GetId(), sessionRecordVersion, now.Add(srv.accessTokenTTL))
	if err != nil {
		return nil, fmt.Errorf("create access token: %w", err)
	}

	refreshToken, err := srv.CreateRefreshToken(sess.GetId(), clientID, now.Add(RefreshTokenTTL), sess.GetIssuedAt().AsTime())
	if err != nil {
		return nil, fmt.Errorf("create refresh token: %w", err)
	}

	resp := &oauth21proto.TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    new(int64(srv.accessTokenTTL.Seconds())),
		RefreshToken: new(refreshToken),
	}

	if len(scopes) > 0 {
		resp.Scope = new(strings.Join(scopes, " "))
	}

	return resp, nil
}

// writeTokenResponse writes the token response to the HTTP response writer.
func writeTokenResponse(w http.ResponseWriter, resp *oauth21proto.TokenResponse) {
	// not using protojson.Marshal here because it emits numbers as strings,
	// which is valid, but for some reason Node.js / mcp typescript SDK doesn't like it
	data, err := json.Marshal(resp)
	if err != nil {
		log.Error().Err(err).Msg("mcp/token: failed to marshal token response")
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}
