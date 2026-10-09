package mcp

import (
	"context"
	"crypto/subtle"
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

// tokenEndpointRealm is the realm reported in the WWW-Authenticate challenge the
// token endpoint sends when Basic client authentication fails.
const tokenEndpointRealm = "pomerium"

// clientAuthFailedDescription is the error_description sent for every client
// authentication failure. It is deliberately uniform: telling the client apart
// from "unknown client" and "wrong secret" would let an unauthenticated caller
// enumerate registered clients.
const clientAuthFailedDescription = "client authentication failed: the client is unknown, or its credentials were rejected"

// clientAuthError is a token request that failed client authentication: the
// client is unknown, or it did not prove possession of its registered secret.
// OAuth 2.1 3.2.3.1 requires these be answered with invalid_client rather than
// invalid_request, and MCP clients treat invalid_client as the signal to discard
// a persisted dynamic client registration and register again.
//
// challengeBasic records whether the client authenticated through the
// Authorization header, which decides the status and challenge the caller
// responds with. It is captured where the credentials are read rather than
// re-derived from the request afterwards.
type clientAuthError struct {
	err error
	// description is sent to the client as error_description. It names the
	// failure without revealing whether the client exists.
	description    string
	challengeBasic bool
}

func (e *clientAuthError) Error() string { return e.err.Error() }
func (e *clientAuthError) Unwrap() error { return e.err }

// status reports the response status and WWW-Authenticate challenge this
// failure must be reported with, per OAuth 2.1 3.2.4.
func (e *clientAuthError) status() (code int, challenge string) {
	if e.challengeBasic {
		return http.StatusUnauthorized, `Basic realm="` + tokenEndpointRealm + `"`
	}
	return http.StatusBadRequest, ""
}

// errServerFault marks a token request that could not be resolved because
// Pomerium itself failed, not because anything was wrong with the request.
var errServerFault = errors.New("server fault")

// isClientIdentityError reports whether an error from getOrFetchClient means the
// client is genuinely unknown or invalid, rather than Pomerium being unable to
// find out. Only the former is a client authentication failure: a databroker
// outage or a client metadata host returning 502 would otherwise answer
// invalid_client, telling every client to discard a registration that is fine.
func isClientIdentityError(err error) bool {
	return status.Code(err) == codes.NotFound ||
		errors.Is(err, ErrClientMetadataValidation) ||
		errors.Is(err, ErrDomainNotAllowed)
}

// attemptedBasicAuth reports whether the client tried to authenticate through
// the Authorization header. A malformed Basic header is still an attempt, and
// RFC 6749 5.2 requires those be answered with a challenge too, so
// r.BasicAuth() succeeding is not the right test.
func attemptedBasicAuth(r *http.Request) bool {
	const prefix = "Basic "
	auth := r.Header.Get("Authorization")
	return len(auth) >= len(prefix) && strings.EqualFold(auth[:len(prefix)], prefix)
}

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
		var authErr *clientAuthError
		switch {
		case errors.As(err, &authErr):
			code, challenge := authErr.status()
			if challenge != "" {
				w.Header().Set("WWW-Authenticate", challenge)
			}
			oauth21.ErrorResponseWithDescription(w, code, oauth21.InvalidClient, authErr.description)
		case errors.Is(err, errServerFault):
			http.Error(w, "internal error", http.StatusInternalServerError)
		default:
			oauth21.ErrorResponse(w, http.StatusBadRequest, oauth21.InvalidRequest)
		}
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

	authReq, authReqVersion, err := srv.storage.GetAuthorizationRequest(ctx, code.Id)
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
	// The request is deleted at the version it was read at, so of several
	// requests redeeming the same code at once exactly one gets past here.
	err = srv.storage.ConsumeAuthorizationRequest(ctx, code.Id, authReqVersion)
	if databroker.IsRecordVersionMismatch(err) {
		log.Ctx(ctx).Info().Str("auth-req-id", code.Id).Msg("mcp/token/auth-code: authorization code was already redeemed")
		oauth21.ErrorResponse(w, http.StatusBadRequest, oauth21.InvalidGrant)
		return
	}
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("mcp/token/auth-code: failed to consume authorization request")
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// The MCP client becomes a dependent of the centralized IdP session the
	// consenting browser session is bound to: its own session.Session, bound to
	// that IDPSession by a Binding the user can revoke.
	idpSess, err := srv.resolveConsentIDPSession(ctx, authReq)
	if err != nil {
		srv.writeGrantError(ctx, w, err, "mcp/token/auth-code: cannot issue for this user")
		return
	}

	now := time.Now()
	sess := newMCPSession(uuid.NewString(), idpSess, now)
	version, err := srv.storage.PutBoundSession(ctx, sess, idpSess.GetId(), map[string]string{
		"mcp_client_id": clientID,
		"client-ip":     httputil.GetClientIP(r),
	})
	if status.Code(err) == codes.NotFound {
		// The user signed out while the session was being bound.
		srv.writeGrantError(ctx, w, fmt.Errorf("%w: %w", errInvalidGrant, err), "mcp/token/auth-code: cannot issue for this user")
		return
	} else if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("mcp/token/auth-code: failed to store mcp client session")
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	resp, err := srv.createTokenResponse(sess, version, clientID, authReq.GetScopes())
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

	// Whether the client presented credentials in the Authorization header,
	// captured once here so every failure below reports the same challenge.
	usedBasicAuth := attemptedBasicAuth(r)
	authFailure := func(description, format string, args ...any) error {
		return &clientAuthError{
			err:            fmt.Errorf(format, args...),
			description:    description,
			challengeBasic: usedBasicAuth,
		}
	}

	log.Ctx(ctx).Debug().
		Str("client-id", tokenReq.GetClientId()).
		Str("grant-type", tokenReq.GetGrantType()).
		Msg("mcp/token: fetching client for authentication")

	clientReg, err := srv.getOrFetchClient(ctx, tokenReq.GetClientId())
	if err != nil {
		log.Ctx(ctx).Debug().Err(err).Str("client-id", tokenReq.GetClientId()).Msg("mcp/token: failed to fetch client")
		if !isClientIdentityError(err) {
			return nil, fmt.Errorf("%w: failed to get client registration: %w", errServerFault, err)
		}
		return nil, authFailure(clientAuthFailedDescription, "failed to get client registration: %w", err)
	}

	m := clientReg.ResponseMetadata.GetTokenEndpointAuthMethod()
	if m == rfc7591v1.TokenEndpointAuthMethodNone {
		return tokenReq, nil
	}

	secret := clientReg.ClientSecret
	if secret == nil {
		return nil, authFailure(clientAuthFailedDescription, "client registration does not have a client secret")
	}
	if expires := secret.ExpiresAt; expires != nil && expires.AsTime().Before(time.Now()) {
		log.Ctx(ctx).Debug().Time("secret-expires", expires.AsTime()).Msg("mcp/token: client secret has expired")
		return nil, authFailure(clientAuthFailedDescription, "client registration client secret has expired")
	}

	// ParseTokenRequest folds credentials from either transport into ClientSecret,
	// so the request itself is what says which mechanism the client actually
	// used. A client is bound to the method it registered for: holding the right
	// secret is not enough if it arrives the wrong way.
	_, _, sentBasicCredentials := r.BasicAuth()
	sentPostCredentials := r.PostForm.Get("client_secret") != ""

	// OAuth 2.1 2.4: a client must not use more than one authentication
	// mechanism. That is a malformed request rather than a bad client.
	if sentBasicCredentials && sentPostCredentials {
		return nil, fmt.Errorf("more than one client authentication mechanism was used")
	}

	// The secret is taken from the transport the client registered for, never
	// from tokenReq: ParseTokenRequest fills that through the query-aware
	// FormValue, so a query parameter could otherwise stand in for the Basic
	// password the client is supposed to prove.
	verifySecret := func(presented string) error {
		if subtle.ConstantTimeCompare([]byte(presented), []byte(secret.Value)) != 1 {
			return authFailure(clientAuthFailedDescription, "client secret mismatch")
		}
		log.Ctx(ctx).Debug().Msg("mcp/token: client secret verified")
		return nil
	}

	log.Ctx(ctx).Debug().
		Str("auth-method", m).
		Bool("sent-basic-credentials", sentBasicCredentials).
		Bool("sent-post-credentials", sentPostCredentials).
		Msg("mcp/token: verifying client authentication")

	switch m {
	case rfc7591v1.TokenEndpointAuthMethodClientSecretBasic:
		basicID, basicSecret, ok := r.BasicAuth()
		if !ok {
			return nil, authFailure(clientAuthFailedDescription,
				"client is registered for client_secret_basic but sent no Basic credentials")
		}
		// The header names the client it authenticates, so it cannot vouch for a
		// request made in another client's name.
		if basicID != tokenReq.GetClientId() {
			return nil, authFailure(clientAuthFailedDescription,
				"Basic credentials are for a different client than the request")
		}
		if err := verifySecret(basicSecret); err != nil {
			return nil, err
		}
	case rfc7591v1.TokenEndpointAuthMethodClientSecretPost:
		if !sentPostCredentials {
			return nil, authFailure(clientAuthFailedDescription,
				"client is registered for client_secret_post but sent no client_secret parameter")
		}
		if err := verifySecret(r.PostForm.Get("client_secret")); err != nil {
			return nil, err
		}
	default:
		return nil, authFailure(clientAuthFailedDescription, "unsupported token endpoint authentication method: %s", m)
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
	resp, err := srv.createTokenResponse(sess, version, clientID, nil)
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

// refreshWriteAttempts bounds how often a refresh retries its conditional write
// after losing it to a rewrite of the session that did not rotate it.
const refreshWriteAttempts = 3

// refreshMCPSession re-issues the MCP client session a refresh token refers to.
//
// The refresh token is bound to the session's Binding: revoking the binding (from
// the bindings page, or by the identity manager when the IdP session is deleted)
// stops refresh at the first check, and the binding is never rewritten here. The
// session record is then re-issued from the IDPSession with a new issued_at,
// which is what rotates the refresh token: a token still carrying the previous
// issued_at is a replayed old generation and is refused.
//
// The re-issue is conditional on the session version read first, and the
// IDPSession is read after it, so the write is refused if anything rewrote the
// session in between. That need not be another presentation of the token: the
// identity manager rewrites every bound session whenever its IdP session
// changes, leaving issued_at alone. A lost write therefore reads the session
// again and refuses the token only if its issued_at moved on, which is a
// concurrent presentation rotating it; otherwise it retries on the fresh state.
// Of several concurrent presentations of one token, exactly one rotates the
// session. A write that fails for any other reason is checked for having landed
// anyway (see recoverLostRefreshWrite) before it is reported as a server error,
// which the client takes to mean its token is still good.
func (srv *Handler) refreshMCPSession(ctx context.Context, payload *opaquetoken.Payload, now time.Time) (*session.Session, uint64, error) {
	sessionID := payload.GetId()

	binding, err := srv.storage.GetActiveBinding(ctx, sessionID)
	if status.Code(err) == codes.NotFound {
		return nil, 0, fmt.Errorf("%w: no active binding for session %q: %w", errInvalidGrant, sessionID, err)
	} else if err != nil {
		return nil, 0, fmt.Errorf("get binding: %w", err)
	}

	for attempt := 1; ; attempt++ {
		stored, storedVersion, err := srv.storage.GetSession(ctx, sessionID)
		if status.Code(err) == codes.NotFound {
			// Revoking the binding or deleting the IdP session deletes the
			// session; this request raced that.
			return nil, 0, fmt.Errorf("%w: session %q no longer exists: %w", errInvalidGrant, sessionID, err)
		} else if err != nil {
			return nil, 0, fmt.Errorf("get session: %w", err)
		}
		if !payload.GetIssuedAt().AsTime().Equal(stored.GetIssuedAt().AsTime()) {
			// On a retry, the write this request lost was the rotation.
			reason := "was rotated"
			if attempt > 1 {
				reason = "was consumed by a concurrent request"
			}
			return nil, 0, fmt.Errorf("%w: refresh token for session %q %s", errInvalidGrant, sessionID, reason)
		}

		idpSess, err := srv.resolveIDPSession(ctx, binding.GetIdpSessionId())
		if err != nil {
			return nil, 0, err
		}

		sess := newMCPSession(sessionID, idpSess, now)
		version, err := srv.storage.PutSession(ctx, sess, storedVersion)
		if err == nil {
			return sess, version, nil
		}
		if !databroker.IsRecordVersionMismatch(err) {
			return srv.recoverLostRefreshWrite(ctx, sess, err)
		}
		if attempt == refreshWriteAttempts {
			return nil, 0, fmt.Errorf("store mcp client session: %w", err)
		}
		log.Ctx(ctx).Debug().
			Str("session-id", sessionID).
			Int("attempt", attempt).
			Msg("mcp/token/refresh: session was rewritten concurrently, retrying")
	}
}

// recoverLostRefreshWrite handles a re-issue that failed for any reason other
// than a version mismatch. Such a write may still have committed with only its
// reply lost (a deadline, a forwarded call whose connection dropped), and then
// the stored issued_at has moved on: the token the client holds is dead, and a
// server error, which tells the client the token is still good, would make its
// retry fail with invalid_grant and force a re-consent. So the session is read
// again. An issued_at equal to the one just written means the write landed, and
// the tokens are minted from the stored record. Otherwise nothing was written,
// the token is still good, and the server error stands.
func (srv *Handler) recoverLostRefreshWrite(ctx context.Context, written *session.Session, writeErr error) (*session.Session, uint64, error) {
	stored, version, err := srv.storage.GetSession(ctx, written.GetId())
	if err != nil {
		return nil, 0, fmt.Errorf("store mcp client session: %w (re-reading it: %w)", writeErr, err)
	}
	if !stored.GetIssuedAt().AsTime().Equal(written.GetIssuedAt().AsTime()) {
		return nil, 0, fmt.Errorf("store mcp client session: %w", writeErr)
	}
	log.Ctx(ctx).Info().Err(writeErr).
		Str("session-id", written.GetId()).
		Msg("mcp/token/refresh: session write reported an error but landed")
	return stored, version, nil
}

// errUnboundSession marks a session a user acts from that is not their browser
// session bound to a centralized IdP session, which is the only kind that can
// consent to an MCP client: it has no binding (it predates bindings, or the
// user signed out), is bound under another protocol (an MCP client presenting
// its own access token), or is bound to another user.
var errUnboundSession = errors.New("not a bound browser session")

// resolveBrowserBinding loads the binding of the session a user acts from and
// checks that it is a browser session of that user. Anything else wraps
// errUnboundSession; a failure to read the binding is returned as is.
func (srv *Handler) resolveBrowserBinding(ctx context.Context, sessionID, userID string) (*idpsession.Binding, error) {
	binding, err := srv.storage.GetActiveBinding(ctx, sessionID)
	if status.Code(err) == codes.NotFound {
		return nil, fmt.Errorf("%w: no binding for session %q: %w", errUnboundSession, sessionID, err)
	} else if err != nil {
		return nil, fmt.Errorf("get binding: %w", err)
	}
	if binding.GetProtocol() != idpsession.BindingProtocol_BINDING_PROTOCOL_BROWSER {
		return nil, fmt.Errorf("%w: session %q is bound as %s", errUnboundSession, sessionID, binding.GetProtocol())
	}
	if binding.GetUserId() != userID {
		return nil, fmt.Errorf("%w: session %q is bound to another user", errUnboundSession, sessionID)
	}
	return binding, nil
}

// resolveConsentIDPSession loads the centralized IdP session the browser
// session that consented at /authorize is bound to. A session that is not the
// user's bound browser session wraps errInvalidGrant: the user signed out
// before the code was redeemed, so no MCP credential may be issued. /authorize
// refuses such a session before issuing a code, so this is a second line of
// defense for codes issued by an older build.
//
// The browser session itself must still be live, too. A session the identity
// manager has not yet reaped keeps its binding for a while after it expired
// or was deleted, and a consent from it must not mint a year-long grant.
func (srv *Handler) resolveConsentIDPSession(ctx context.Context, authReq *oauth21proto.AuthorizationRequest) (*idpsession.IDPSession, error) {
	sessionID, userID := authReq.GetSessionId(), authReq.GetUserId()
	binding, err := srv.resolveBrowserBinding(ctx, sessionID, userID)
	if errors.Is(err, errUnboundSession) {
		return nil, fmt.Errorf("%w: %w", errInvalidGrant, err)
	} else if err != nil {
		return nil, err
	}

	browser, _, err := srv.storage.GetSession(ctx, sessionID)
	if status.Code(err) == codes.NotFound {
		return nil, fmt.Errorf("%w: browser session %q is gone: %w", errInvalidGrant, sessionID, err)
	} else if err != nil {
		return nil, fmt.Errorf("get browser session: %w", err)
	}
	if browser.GetUserId() != userID {
		return nil, fmt.Errorf("%w: browser session %q belongs to another user", errInvalidGrant, sessionID)
	}
	if expiresAt := browser.GetExpiresAt(); expiresAt != nil && !expiresAt.AsTime().After(time.Now()) {
		return nil, fmt.Errorf("%w: browser session %q expired at %s", errInvalidGrant, sessionID, expiresAt.AsTime())
	}

	idpSess, err := srv.resolveIDPSession(ctx, binding.GetIdpSessionId())
	if err != nil {
		return nil, err
	}
	if idpSess.GetUserId() != userID {
		return nil, fmt.Errorf("%w: idp session %q belongs to another user", errInvalidGrant, idpSess.GetId())
	}
	return idpSess, nil
}

// resolveIDPSession loads a centralized IdP session. A missing one wraps
// errInvalidGrant: the user signed out or the provider revoked them, so no MCP
// credential may be issued on their behalf.
func (srv *Handler) resolveIDPSession(ctx context.Context, id string) (*idpsession.IDPSession, error) {
	idpSess, err := srv.storage.GetValidIDPSession(ctx, id)
	if status.Code(err) == codes.NotFound {
		return nil, fmt.Errorf("%w: no centralized idp session %q: %w", errInvalidGrant, id, err)
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
// expired before the next propagation. With an IdP that issues no refresh
// token the session is deleted at that point regardless, flag or not, as a
// browser session is.
func newMCPSession(id string, idpSess *idpsession.IDPSession, now time.Time) *session.Session {
	return idpsession.IssueSession(id, idpSess, now, RefreshTokenTTL)
}

// createTokenResponse mints the access and refresh tokens for a just-issued MCP
// client session, as of the session's issued_at.
func (srv *Handler) createTokenResponse(
	sess *session.Session,
	sessionRecordVersion uint64,
	clientID string,
	scopes []string,
) (*oauth21proto.TokenResponse, error) {
	issuedAt := sess.GetIssuedAt().AsTime()
	accessToken, err := srv.GetAccessTokenForSessionWithVersion(sess.GetId(), sessionRecordVersion, issuedAt.Add(srv.accessTokenTTL))
	if err != nil {
		return nil, fmt.Errorf("create access token: %w", err)
	}

	refreshToken, err := srv.CreateRefreshToken(sess.GetId(), clientID, issuedAt.Add(RefreshTokenTTL), issuedAt)
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
