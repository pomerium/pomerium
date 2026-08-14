package oidcprovider

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"strings"
	"time"

	"filippo.io/keygen"
	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/oauth2"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/oidcprovider/tokens"
	"github.com/pomerium/pomerium/pkg/identity"
	"github.com/pomerium/pomerium/pkg/telemetry/trace"
)

const CallbackPath = "/oidc/callback"

type Handlers struct {
	issuerURL string

	stateEncryptor        *tokens.StateEncryptor
	codeEncryptor         *tokens.CodeEncryptor
	accessTokenEncryptor  *tokens.AccessTokenEncryptor
	refreshTokenEncryptor *tokens.RefreshTokenEncryptor

	// underlying identity provider
	idp identity.Authenticator

	// key set for ID tokens that we sign
	publicJWKS jose.JSONWebKeySet

	idTokenSigner jose.Signer
}

func NewHandlers(
	ctx context.Context,
	o *config.Options,
) (*Handlers, error) {
	// TODO: instrument these handler methods for tracing
	tracerProvider := trace.NewTracerProvider(ctx, "Authenticate")
	defaultIDP, err := o.GetIdentityProviderForPolicy(nil)
	if err != nil {
		return nil, err
	}
	issuerURL := o.AuthenticateURLString
	redirectURLString := issuerURL + CallbackPath
	redirectURL, err := url.Parse(redirectURLString)
	if err != nil {
		return nil, err
	}
	idp, err := identity.GetIdentityProvider(ctx, tracerProvider, defaultIDP, redirectURL, true)
	if err != nil {
		return nil, err
	}
	secret, err := o.GetSharedKey()
	if err != nil {
		return nil, err
	}
	aead, err := tokens.DeriveEncryptionCipher(secret)
	if err != nil {
		return nil, err
	}
	jwks, err := deriveJWKS(secret)
	if err != nil {
		return nil, err
	}
	idTokenSigner, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: jwks.Keys[0]},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		return nil, err
	}

	var publicJWKS jose.JSONWebKeySet
	publicJWKS.Keys = make([]jose.JSONWebKey, len(jwks.Keys))
	for i := range jwks.Keys {
		publicJWKS.Keys[i] = jwks.Keys[i].Public()
	}

	return &Handlers{
		issuerURL:             issuerURL,
		codeEncryptor:         tokens.NewCodeEncryptor(aead),
		accessTokenEncryptor:  tokens.NewAccessTokenEncryptor(aead),
		refreshTokenEncryptor: tokens.NewRefreshTokenEncryptor(aead),
		stateEncryptor:        tokens.NewStateEncryptor(aead),
		idp:                   idp,
		idTokenSigner:         idTokenSigner,
		publicJWKS:            publicJWKS,
	}, nil
}

func deriveJWKS(sharedSecret []byte) (*jose.JSONWebKeySet, error) {
	// XXX: generate a random key and store in databroker?
	r2 := hkdf.New(sha256.New, sharedSecret, nil, []byte("authenticate-oidc-signing-key"))
	signingKey, err := keygen.ECDSALegacy(elliptic.P256(), r2)
	if err != nil {
		return nil, err
	}
	jwk := jose.JSONWebKey{
		Key:       signingKey,
		Use:       "sig",
		Algorithm: string(jose.ES256),
	}
	thumbprint, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, err
	}
	jwk.KeyID = hex.EncodeToString(thumbprint)

	jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}}
	return &jwks, nil
}

func (h *Handlers) Mount(r *mux.Router) {
	r.Path("/oidc/auth").Methods(http.MethodGet).HandlerFunc(h.handleAuth)
	r.Path("/oidc/token").Methods(http.MethodPost).HandlerFunc(h.handleToken)
	r.Path("/oidc/userinfo").Methods(http.MethodGet).HandlerFunc(h.handleUserInfo)
	r.Path("/.well-known/jwks.json").Methods(http.MethodGet).HandlerFunc(h.handleJWKS)
	r.Path("/.well-known/openid-configuration").Methods(http.MethodGet).HandlerFunc(h.handleOIDCConfiguration)
	r.Path(CallbackPath).Methods(http.MethodGet).HandlerFunc(h.handleCallback)
}

func (h *Handlers) handleOIDCConfiguration(w http.ResponseWriter, _ *http.Request) {
	var rootURL *url.URL
	rootURL, _ = url.Parse(h.issuerURL)
	config := map[string]interface{}{
		"issuer":                                h.issuerURL,
		"authorization_endpoint":                rootURL.ResolveReference(&url.URL{Path: "/oidc/auth"}).String(),
		"token_endpoint":                        rootURL.ResolveReference(&url.URL{Path: "/oidc/token"}).String(),
		"jwks_uri":                              rootURL.ResolveReference(&url.URL{Path: "/.well-known/jwks.json"}).String(),
		"userinfo_endpoint":                     rootURL.ResolveReference(&url.URL{Path: "/oidc/userinfo"}).String(),
		"end_session_endpoint":                  rootURL.ResolveReference(&url.URL{Path: "/.pomerium/sign_out"}).String(),
		"grant_types_supported":                 []string{"authorization_code"},
		"id_token_signing_alg_values_supported": []string{"ES256"},
		"response_types_supported":              []string{"code"},
		"scopes_supported":                      []string{"openid"},
	}
	serveJSON(w, config)
}

func (h *Handlers) handleAuth(w http.ResponseWriter, r *http.Request) {
	request, err := validateAuthRequestJWT(r.FormValue("request"), h.issuerURL, time.Now())
	if err != nil {
		log.Ctx(r.Context()).Info().Err(err).Msg("oidc: auth request failed validation")
		(&HTMLErrorResponse{
			Status:      http.StatusBadRequest,
			Description: "Request object missing or invalid",
		}).serve(w, r)
		return
	}

	// Assign a request UUID (just for event logging).
	requestUUID := uuid.NewString()

	state := h.stateEncryptor.Encrypt(&tokens.StatePayload{
		ClientID:      request.ClientID,
		ClientKey:     request.Key,
		RequestUUID:   requestUUID,
		Expiration:    time.Now().Add(24 * time.Hour),
		OriginalState: request.State,
	})

	err = h.idp.SignIn(w, r, state)
	if err != nil {
		(&HTMLErrorResponse{
			Status: http.StatusInternalServerError,
		}).serve(w, r)
	}
}

type AuthRequestClaims struct {
	ClientID        string `json:"client_id"`
	State           string `json:"state"`
	PomeriumVersion string `json:"pomerium_version"`
}

type ValidatedAuthRequest struct {
	AuthRequestClaims
	Key             ed25519.PublicKey
	PomeriumVersion string
}

func validateAuthRequestJWT(requestString, expectedAudience string, now time.Time) (*ValidatedAuthRequest, error) {
	if requestString == "" {
		return nil, fmt.Errorf("no request object provided")
	}

	request, err := jwt.ParseSigned(requestString)
	if err != nil {
		return nil, fmt.Errorf("couldn't parse request object: %w", err)
	} else if n := len(request.Headers); n != 1 {
		return nil, fmt.Errorf("expected request object to have one signature, but had %d", n)
	}

	header := request.Headers[0]
	if header.Algorithm != string(jose.EdDSA) {
		return nil, fmt.Errorf("request object has unsupported signing algorithm %q", header.Algorithm)
	}
	jwk := header.JSONWebKey
	if jwk == nil {
		return nil, fmt.Errorf("request object header does not have signing key")
	}
	key, ok := jwk.Key.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("expected request object signing key to be of type ed25519.PublicKey, found %T", jwk.Key)
	}

	var claims struct {
		jwt.Claims
		AuthRequestClaims
	}
	if err := request.Claims(jwk, &claims); err != nil {
		return nil, fmt.Errorf("couldn't parse request object claims: %w", err)
	}

	if err := claims.Validate(jwt.Expected{
		Issuer:   claims.ClientID,
		Audience: jwt.Audience{expectedAudience},
		Time:     now,
	}); err != nil {
		return nil, fmt.Errorf("request object claims failed validation: %w", err)
	}

	if err := validateClientID(claims.ClientID); err != nil {
		return nil, fmt.Errorf("invalid request client ID: %w", err)
	}

	return &ValidatedAuthRequest{
		AuthRequestClaims: claims.AuthRequestClaims,
		Key:               key,
		PomeriumVersion:   claims.PomeriumVersion,
	}, nil
}

func validateClientID(clientID string) error {
	u, err := url.Parse(clientID)
	if err != nil {
		return err
	} else if u.Scheme != "https" {
		return fmt.Errorf(`URL scheme must be "https", got %q`, u.Scheme)
	} else if u.RawQuery != "" {
		return fmt.Errorf("URL must not contain query parameters")
	} else if u.Path != "" {
		return fmt.Errorf("URL must not contain a path")
	} else if u.Fragment != "" {
		return fmt.Errorf("URL must not contain a fragment")
	}
	return nil
}

// handleCallback handles a callback endpoint request, serving a redirect
// with the authorization code or error details.
func (h *Handlers) handleCallback(w http.ResponseWriter, r *http.Request) {
	// Propagate any query parameters (e.g. error, error_description), but
	// rewrite the 'state' and 'code' (if present).
	q := r.URL.Query()

	state, err := h.stateEncryptor.Decrypt(q.Get("state"))
	if err != nil {
		log.Ctx(r.Context()).Info().Err(err).Msg("oidc: callback state invalid")
		(&HTMLErrorResponse{
			Status:      http.StatusBadRequest,
			Description: "State missing or invalid",
		}).serve(w, r)
		return
	} else if time.Until(state.Expiration) < 0 {
		log.Ctx(r.Context()).Info().
			Str("client-id", state.ClientID).
			Time("expiration", state.Expiration.UTC()).
			Msg("oidc: callback state expired")
		(&HTMLErrorResponse{
			Status:      http.StatusBadRequest,
			Description: "Request timed out. Please sign in again.",
		}).serve(w, r)
		return
	}
	q.Set("state", state.OriginalState)

	if code := q.Get("code"); code != "" {
		q.Set("code", h.codeEncryptor.Encrypt(&tokens.CodePayload{
			ClientKey:    state.ClientKey,
			RequestUUID:  state.RequestUUID,
			Expiration:   time.Now().Add(5 * time.Minute),
			OriginalCode: code,
		}, state.ClientID))
	}

	redirectURI := state.ClientID + "/oauth2/callback?" + q.Encode()
	http.Redirect(w, r, redirectURI, http.StatusFound)
}

// handleToken handles a token endpoint request, exchanging an authorization
// code for an access token and ID token. This endpoint is not user-facing, so
// errors are returned as JSON objects.
func (h *Handlers) handleToken(w http.ResponseWriter, r *http.Request) {
	req, err := h.validateTokenRequest(r, time.Now())
	if err != nil {
		log.Ctx(r.Context()).Info().Err(err).Msg("oidc: token request invalid")
		(&JSONErrorResponse{
			Status: http.StatusBadRequest,
			Error:  errorCodeOrDefault(err, "invalid_request"),
		}).serve(w, r)
		return
	}

	token, userClaims, err := req.GetToken(r.Context())
	if err != nil {
		log.Ctx(r.Context()).Error().Err(err).Msg("oidc: token exchange failed")
		(&JSONErrorResponse{
			Status: http.StatusInternalServerError,
			Error:  "server_error",
		}).serve(w, r)
		return
	}

	idToken, err := h.issueIDToken(userClaims.Claims, req.ClientID)
	if err != nil {
		log.Ctx(r.Context()).Error().Err(err).Msg("oidc: couldn't issue ID token")
		(&JSONErrorResponse{
			Status: http.StatusInternalServerError,
			Error:  "server_error",
		}).serve(w, r)
		return
	}

	resp := map[string]any{
		"access_token": h.accessTokenEncryptor.Encrypt(token.AccessToken),
		"token_type":   "Bearer",
		"id_token":     idToken,
		"expires_in":   token.ExpiresIn,
	}
	if len(token.RefreshToken) > 0 {
		resp["refresh_token"] = h.refreshTokenEncryptor.Encrypt(&tokens.RefreshPayload{
			ClientKey: req.ClientKey,
			Token:     token.RefreshToken,
		}, req.ClientID)
	}

	serveJSON(w, resp)
}

// Grant represents an IdP operation for granting a token.
type Grant interface {
	GetToken(context.Context) (*oauth2.Token, *identity.SessionClaims, error)
}

// authorizationCodeGrant completes the authorization code flow and logs an
// AuthEventSignInComplete event.
type authorizationCodeGrant struct {
	idp identity.Authenticator

	clientID        string
	payload         *tokens.CodePayload
	pomeriumVersion string
}

func (a *authorizationCodeGrant) GetToken(ctx context.Context) (*oauth2.Token, *identity.SessionClaims, error) {
	var userClaims identity.SessionClaims
	token, err := a.idp.Authenticate(ctx, a.payload.OriginalCode, &userClaims)
	if err != nil {
		return nil, nil, err
	}

	return token, &userClaims, nil
}

// refreshTokenGrant performs an IdP refresh request.
type refreshTokenGrant struct {
	idp identity.Authenticator

	refreshToken string
}

func (a *refreshTokenGrant) GetToken(ctx context.Context) (*oauth2.Token, *identity.SessionClaims, error) {
	var userClaims identity.SessionClaims
	token, err := a.idp.Refresh(ctx, &oauth2.Token{RefreshToken: a.refreshToken}, &userClaims)
	if err != nil {
		return nil, nil, err
	}
	return token, &userClaims, nil
}

type ValidatedTokenRequest struct {
	Grant

	ClientID  string
	ClientKey ed25519.PublicKey
}

// TODO: make this an exported constant in the pomerium/pomerium repo
const clientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

const timestampFormat = "2006-01-02 15:04:05 Z07"

func (h *Handlers) validateTokenRequest(r *http.Request, now time.Time) (*ValidatedTokenRequest, error) {
	// From the OIDC spec §3.1.3.2:
	//
	//  The Authorization Server MUST validate the Token Request as follows:
	//  1. Authenticate the Client if it was issued Client Credentials or if it
	//     uses another Client Authentication method, per Section 9.
	//  2. Ensure the Authorization Code was issued to the authenticated Client.
	//  3. Verify that the Authorization Code is valid.
	//  4. If possible, verify that the Authorization Code has not been
	//     previously used.
	//  5. Ensure that the redirect_uri parameter value is identical to the
	//     redirect_uri parameter value that was included in the initial
	//     Authorization Request. If the redirect_uri parameter value is not
	//     present when there is only one registered redirect_uri value, the
	//     Authorization Server MAY return an error (since the Client should
	//     have included the parameter) or MAY proceed without an error (since
	//     OAuth 2.0 permits the parameter to be omitted in this case).
	//  6. Verify that the Authorization Code used was issued in response to an
	//     OpenID Connect Authentication Request (so that an ID Token will be
	//     returned from the Token Endpoint).
	//
	// Implementation notes:
	//  - We do not currently implement (4).
	//  - For (5), we treat the client as if it effectively has a single
	//    registered redirect_uri. The client ID must be set to the authenticate
	//    service URL, so the redirect_uri can be constructed from this URL.

	// For (1): we require the private_key_jwt client authentication method.
	assertionType := r.FormValue("client_assertion_type")
	assertion := r.FormValue("client_assertion")
	if assertionType != clientAssertionType || assertion == "" {
		return nil, fmt.Errorf("private_key_jwt client authentication not present")
	}
	parsed, err := jwt.ParseSigned(assertion)
	if err != nil {
		return nil, fmt.Errorf("couldn't parse client_assertion: %w", err)
	}

	// Note that the JWT signing key is contained in the encrypted payload, so
	// we need to read the (unverified) client ID first before we can verify
	// the JWT signature. We verify the JWT signature below.
	var clientClaims struct {
		jwt.Claims
		PomeriumVersion string `json:"pomerium_version"`
	}
	err = parsed.UnsafeClaimsWithoutVerification(&clientClaims)
	if err != nil {
		return nil, fmt.Errorf("invalid client assertion: %w", err)
	}

	clientID := clientClaims.Subject
	var clientKey ed25519.PublicKey
	var grant Grant

	// We support two grant types: authorization_code and refresh_token.
	grantType := r.FormValue("grant_type")
	switch grantType {
	case "authorization_code":
		// Decrypt authorization code and verify JWT signature. This fulfills
		// requirements (1)-(3) and (6). Note that we satisfy (2) and (6) by using
		// the "additional data" in the AEAD cipher. We use a fixed prefix (specific
		// to OIDC authorization codes) concatenated with the client ID.
		payload, err := h.codeEncryptor.Decrypt(r.FormValue("code"), clientID)
		if err != nil {
			return nil, fmt.Errorf("couldn't decrypt authorization code: %w", err)
		} else if payload.Expiration.Before(now) {
			return nil, fmt.Errorf("authorization code expired at %s",
				payload.Expiration.UTC().Format(timestampFormat))
		}
		clientKey = payload.ClientKey
		grant = &authorizationCodeGrant{
			idp:             h.idp,
			clientID:        clientID,
			payload:         payload,
			pomeriumVersion: clientClaims.PomeriumVersion,
		}
	case "refresh_token":
		t := r.FormValue("refresh_token")
		payload, err := h.refreshTokenEncryptor.Decrypt(t, clientID)
		if err != nil {
			return nil, fmt.Errorf("couldn't decrypt refresh token: %w", err)
		}
		clientKey = payload.ClientKey
		grant = &refreshTokenGrant{
			idp:          h.idp,
			refreshToken: payload.Token,
		}
	default:
		return nil, &errorCodeError{
			errorCode:   "unsupported_grant_type",
			errorString: fmt.Sprintf("unsupported grant type requested: %q", grantType),
		}
	}

	// Verify the client assertion JWT signature now that we have the client key.
	if err := parsed.Claims(clientKey); err != nil {
		return nil, fmt.Errorf("invalid client assertion: %w", err)
	} else if err := clientClaims.Validate(jwt.Expected{
		Issuer:   clientClaims.Subject, // subject and issuer should be equal
		Audience: jwt.Audience{h.issuerURL + "/oidc/token"},
		Time:     now,
	}); err != nil {
		return nil, fmt.Errorf("invalid client assertion: %w", err)
	}

	// For (5): if a redirect_uri is provided in the request, it must match what
	// we expect from the client ID.
	redirectURI := clientID + "/oauth2/callback"
	if u := r.FormValue("redirect_uri"); u != "" && u != redirectURI {
		return nil, fmt.Errorf("unexpected redirect_uri provided, want %q, got %q", redirectURI, u)
	}

	// Additional requirement specific to JWT authentication from RFC 7523:
	//
	//  The JWT MUST contain an "exp" (expiration time) claim that
	//  limits the time window during which the JWT can be used.  The
	//  authorization server MUST reject any JWT with an expiration time
	//  that has passed, subject to allowable clock skew between
	//  systems.  Note that the authorization server may reject JWTs
	//  with an "exp" claim value that is unreasonably far in the
	//  future.
	if clientClaims.Expiry == nil {
		return nil, fmt.Errorf("invalid client assertion: missing expiry (exp)")
	} else if clientClaims.Expiry.Time().Sub(now) > time.Hour {
		return nil, fmt.Errorf("invalid client assertion: expiration too far in the future (%d)", *clientClaims.Expiry)
	}

	return &ValidatedTokenRequest{
		Grant:     grant,
		ClientID:  clientID,
		ClientKey: clientKey,
	}, nil
}

func (h *Handlers) issueIDToken(claims identity.Claims, clientID string) (string, error) {
	// Make sure we have a subject.
	if s, _ := claims["sub"].(string); s == "" {
		return "", fmt.Errorf("refusing to issue ID token with missing subject")
	}

	// Clone the claims data, converting to a plain map type for compatibility
	// with the go-jose package.
	payload := maps.Clone[map[string]any](claims)

	// Rewrite "aud" and "iss".
	payload["aud"] = clientID
	payload["iss"] = h.issuerURL

	token, err := jwt.Signed(h.idTokenSigner).Claims(payload).CompactSerialize()
	if err != nil {
		return "", err
	}
	return token, nil
}

// handleUserInfo handles a request to the user info endpoint.
func (h *Handlers) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	authz := r.Header.Get("Authorization")
	if authz == "" {
		log.Ctx(r.Context()).Info().Msg("oidc: userinfo request missing authorization header")
		(&JSONErrorResponse{
			Status: http.StatusBadRequest,
			Error:  "invalid_request",
		}).serve(w, r)
		return
	}

	if strings.HasPrefix(authz, "Bearer ") {
		authz = authz[len("Bearer "):]
	} else {
		log.Ctx(r.Context()).Info().Msg("oidc: userinfo request missing bearer token")
		(&JSONErrorResponse{
			Status: http.StatusBadRequest,
			Error:  "invalid_request",
		}).serve(w, r)
		return
	}

	accessToken, err := h.accessTokenEncryptor.Decrypt(authz)
	if err != nil {
		log.Ctx(r.Context()).Info().Err(err).Msg("oidc: userinfo request has invalid access token")
		(&JSONErrorResponse{
			Status: http.StatusUnauthorized,
			Error:  "invalid_token",
		}).serve(w, r)
		return
	}

	ot := &oauth2.Token{AccessToken: accessToken}
	var claims map[string]any
	if err := h.idp.UpdateUserInfo(r.Context(), ot, &claims); err != nil {
		log.Ctx(r.Context()).Error().Err(err).Msg("oidc: userinfo error")
		(&JSONErrorResponse{
			Status: http.StatusInternalServerError,
			Error:  "server_error",
		}).serve(w, r)
		return
	}

	// TODO: remove any JWT-specific claims

	serveJSON(w, claims)
}

func (h *Handlers) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	serveJSON(w, h.publicJWKS)
}

func serveJSON(w http.ResponseWriter, obj any) {
	bs, err := json.Marshal(obj)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(bs)
}

type errorCodeError struct { //nolint:errname
	errorCode   string
	errorString string
}

func (e errorCodeError) Error() string {
	return e.errorString
}

func errorCodeOrDefault(err error, defaultErrorCode string) string {
	var e *errorCodeError
	if errors.As(err, &e) {
		return e.errorCode
	}
	return defaultErrorCode
}
