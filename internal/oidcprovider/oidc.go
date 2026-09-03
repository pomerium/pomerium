package oidcprovider

import (
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"filippo.io/keygen"
	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/hkdf"
	"google.golang.org/protobuf/proto"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/handlers"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/oidcprovider/tokens"
	"github.com/pomerium/pomerium/pkg/endpoints"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/identity"
)

const nonceSizeLimit = 300 // not part of the OIDC spec

type Handlers struct {
	issuerURL string

	stateEncryptor        *tokens.StateEncryptor
	codeEncryptor         *tokens.CodeEncryptor
	accessTokenEncryptor  *tokens.AccessTokenEncryptor
	refreshTokenEncryptor *tokens.RefreshTokenEncryptor

	// key set for ID tokens that we sign
	publicJWKS jose.JSONWebKeySet

	idTokenSigner    jose.Signer
	getSessionHandle func(*http.Request) (*session.Handle, error)
	getUserInfoData  func(*http.Request, *session.Handle) handlers.UserInfoData
}

// what do we actually need from the Options?
// 1. some way to get user/session info -- probably a databroker client?
// 2. the authenticate URL (used for issuer + internal redirect URL)
// 3. signing key for ID tokens
// 4. some secret for symmetric encryption (AEAD)
func NewHandlers(
	ctx context.Context,
	getSessionHandle func(*http.Request) (*session.Handle, error),
	getUserInfoData func(*http.Request, *session.Handle) handlers.UserInfoData,
	o *config.Options,
) (*Handlers, error) {
	issuerURL := o.AuthenticateURLString
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
		jose.SigningKey{Algorithm: jose.RS256, Key: jwks.Keys[0]},
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
		idTokenSigner:         idTokenSigner,
		publicJWKS:            publicJWKS,
		getSessionHandle:      getSessionHandle,
		getUserInfoData:       getUserInfoData,
	}, nil
}

func deriveJWKS(sharedSecret []byte) (*jose.JSONWebKeySet, error) {
	r := hkdf.New(sha256.New, sharedSecret, nil, []byte("authenticate-oidc-signing-key"))
	var seed [32]byte
	if _, err := io.ReadFull(r, seed[:]); err != nil {
		return nil, err
	}
	signingKey, err := keygen.RSA(2048, seed[:])
	if err != nil {
		return nil, err
	}
	jwk := jose.JSONWebKey{
		Key:       signingKey,
		Use:       "sig",
		Algorithm: string(jose.RS256),
	}
	thumbprint, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, err
	}
	jwk.KeyID = hex.EncodeToString(thumbprint)

	jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}}
	return &jwks, nil
}

func (h *Handlers) HandleOIDCConfiguration(w http.ResponseWriter, _ *http.Request) {
	var rootURL *url.URL
	rootURL, _ = url.Parse(h.issuerURL)
	config := map[string]interface{}{
		"issuer":                                h.issuerURL,
		"authorization_endpoint":                rootURL.ResolveReference(&url.URL{Path: endpoints.PathOIDCAuth}).String(),
		"token_endpoint":                        rootURL.ResolveReference(&url.URL{Path: endpoints.PathOIDCToken}).String(),
		"jwks_uri":                              rootURL.ResolveReference(&url.URL{Path: endpoints.PathOIDCJWKS}).String(),
		"userinfo_endpoint":                     rootURL.ResolveReference(&url.URL{Path: endpoints.PathOIDCUserInfo}).String(),
		"end_session_endpoint":                  rootURL.ResolveReference(&url.URL{Path: endpoints.PathPomeriumSignOut}).String(),
		"grant_types_supported":                 []string{"authorization_code"},
		"subject_types_supported":               []string{"public"},
		"code_challenge_methods_supported":      []string{"S256"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post"}, // XXX: support client_secret_basic
		"response_types_supported":              []string{"code"},
		"scopes_supported":                      []string{"openid"},
	}
	serveJSON(w, config)
}

func (h *Handlers) HandleAuth(w http.ResponseWriter, r *http.Request) {
	log.Ctx(r.Context()).Info().Str("headers", fmt.Sprint(r.Header)).Msg(" *** oidcprovider.Handlers.HandleAuth")

	validated, err := validateAuthRequest(r)
	if err != nil {
		// If the redirect_uri is not valid, we must not redirect to it.
		// See RFC 6749 §4.1.2.1.
		if errors.Is(err, errInvalidRedirectURI) || validated == nil {
			(&httputil.HTTPError{
				Status:      http.StatusBadRequest,
				Description: err.Error(),
			}).ErrorResponse(r.Context(), w, r)
			return
		}

		// Any other error should be redirected.
		e := errorCodeError{
			errorCode:   "invalid_request",
			errorString: err.Error(),
		}
		http.Redirect(w, r, validated.ErrorRedirectURL(e), http.StatusFound)
		return
	}

	s, err := h.getSessionToken(r)
	if err != nil {
		log.Ctx(r.Context()).Error().Err(err).Msg("oidcprovider: could not retrieve session for auth request")
		e := errorCodeError{
			errorCode:   "server_error",
			errorString: "could not retrieve session",
		}
		http.Redirect(w, r, validated.ErrorRedirectURL(e), http.StatusFound)
		return
	}

	q := url.Values{}
	q.Set("code", h.codeEncryptor.Encrypt(&tokens.CodePayload{
		RedirectURI:       validated.RedirectURI,
		Expiration:        time.Now().Add(5 * time.Minute),
		S256CodeChallenge: validated.S256CodeChallenge,
		Nonce:             r.FormValue("nonce"),
		SessionToken:      s,
	}, validated.ClientID))
	q.Set("state", r.FormValue("state"))
	http.Redirect(w, r, validated.RedirectURI+"?"+q.Encode(), http.StatusFound)
}

func (h *Handlers) getSessionToken(r *http.Request) (string, error) {
	s, err := h.getSessionHandle(r)
	if err != nil {
		return "", err
	}
	sessionBytes, err := proto.Marshal(s)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sessionBytes), nil
}

var errInvalidRedirectURI = errors.New("invalid redirect_uri")

type validatedAuthRequest struct {
	ClientID          string
	RedirectURI       string
	State             string
	Nonce             string
	S256CodeChallenge string
}

func validateAuthRequest(r *http.Request) (*validatedAuthRequest, error) {
	clientID := r.FormValue("client_id")
	if clientID == "" {
		return nil, errors.New("client_id is required")
	}
	redirectURI := r.FormValue("redirect_uri")
	if redirectURI == "" {
		return nil, errors.New("redirect_uri is required")
	} else if err := validateClientIDAndRedirectURI(clientID, redirectURI); err != nil {
		return nil, fmt.Errorf("%w: %v", errInvalidRedirectURI, err)
	}

	validated := &validatedAuthRequest{
		ClientID:    clientID,
		RedirectURI: redirectURI,
		State:       r.FormValue("state"),
	}

	var err error
	validated.S256CodeChallenge, err = validateCodeChallenge(
		r.FormValue("code_challenge_method"), r.FormValue("code_challenge"))
	if err != nil {
		return validated, err
	}

	nonce := r.FormValue("nonce")
	if len(nonce) > nonceSizeLimit {
		return validated, errors.New("nonce too large")
	}
	validated.Nonce = nonce

	return validated, nil
}

func (v *validatedAuthRequest) ErrorRedirectURL(e errorCodeError) string {
	q := url.Values{
		"error": {e.errorCode},
	}
	if e.errorString != "" {
		q.Add("error_description", e.errorString)
	}
	if v.State != "" {
		q.Add("state", v.State)
	}
	return v.RedirectURI + "?" + q.Encode()
}

// validateClientIDAndRedirectURI verifies that the client_id and redirect_uri
// are both valid URLs, and that the redirect_uri matches the client_id. To be
// considered valid, a URL must:
//   - have the scheme "https"
//   - not contain a username/password
//   - not contain a query
//   - not contain a fragment
//   - not contain empty or relative path components
//
// The redirect_uri is considered to match the client_id if:
//   - the host is identical
//   - the redirect_uri path is equal to or is a child of the client_id path
func validateClientIDAndRedirectURI(clientID, redirectURI string) error {
	clientURL, err := parseURL(clientID)
	if err != nil {
		return fmt.Errorf("invalid client_id: %w", err)
	}
	parsedRedirectURI, err := parseURL(redirectURI)
	if err != nil {
		return fmt.Errorf("invalid redirect_uri: %w", err)
	}
	childPath, ok := strings.CutPrefix(parsedRedirectURI.Path, clientURL.Path)
	if !ok || (len(childPath) > 0 && childPath[0] != '/') || parsedRedirectURI.Host != clientURL.Host {
		return fmt.Errorf("redirect_uri %q does not match client_id %q", redirectURI, clientID)
	}
	return nil
}

func parseURL(originalURL string) (*url.URL, error) {
	cleanPath := func(p string) string {
		if p == "" {
			return ""
		}
		return path.Clean(p)
	}

	u, err := url.Parse(originalURL)
	if err != nil {
		return nil, err
	} else if u.Scheme != "https" {
		return nil, fmt.Errorf(`URL scheme must be "https", got %q`, u.Scheme)
	} else if u.User != nil {
		return nil, fmt.Errorf("URL must not contain username or password")
	} else if u.RawQuery != "" {
		return nil, fmt.Errorf("URL must not contain query parameters")
	} else if u.Fragment != "" {
		return nil, fmt.Errorf("URL must not contain a fragment")
	} else if cleaned := (&url.URL{
		Scheme: "https",
		Host:   u.Host,
		Path:   cleanPath(u.Path),
	}).String(); cleaned != originalURL {
		return nil, fmt.Errorf("invalid URL path")
	}
	return u, nil
}

func validateCodeChallenge(method, challenge string) (string, error) {
	switch method {
	case "":
		return "", nil
	case "S256":
		b, err := base64.URLEncoding.DecodeString(challenge)
		if err != nil || len(b) != sha256.Size {
			return "", errors.New("invalid code_challenge")
		}
		return challenge, nil
	default:
		return "", fmt.Errorf("unsupported code_challenge_method %q", method)
	}
}

// HandleToken handles a token endpoint request, exchanging an authorization
// code for an access token and ID token. This endpoint is not user-facing, so
// errors are returned as JSON objects.
func (h *Handlers) HandleToken(w http.ResponseWriter, r *http.Request) {
	req, err := h.validateTokenRequest(r, time.Now())
	if err != nil {
		log.Ctx(r.Context()).Info().Err(err).Msg("oidc: token request invalid")
		(&JSONErrorResponse{
			Status: http.StatusBadRequest,
			Error:  errorCodeOrDefault(err, "invalid_request"),
		}).serve(w, r)
		return
	}

	sh, err := h.parseSessionHandle(req.SessionHandle)
	if err != nil {
		log.Ctx(r.Context()).Info().Err(err).Msg("oidc: session handle parse error")
		(&JSONErrorResponse{
			Status: http.StatusInternalServerError,
			Error:  errorCodeOrDefault(err, "server_error"),
		}).serve(w, r)
		return
	}

	data := h.getUserInfoData(r, sh)
	// XXX: why is there no error value?

	idToken, err := h.issueIDToken(&data, req.ClientID, req.Nonce)
	if err != nil {
		log.Ctx(r.Context()).Error().Err(err).Msg("oidc: couldn't issue ID token")
		(&JSONErrorResponse{
			Status: http.StatusInternalServerError,
			Error:  "server_error",
		}).serve(w, r)
		return
	}

	resp := map[string]any{
		"access_token": h.accessTokenEncryptor.Encrypt(req.SessionHandle),
		"token_type":   "Bearer",
		"id_token":     idToken,
		"expires_in":   time.Until(data.Session.ExpiresAt.AsTime()),
	}

	serveJSON(w, resp)
}

func (h *Handlers) parseSessionHandle(s string) (*session.Handle, error) {
	sessionBytes, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	var sh session.Handle
	if err := proto.Unmarshal(sessionBytes, &sh); err != nil {
		return nil, err
	}
	return &sh, nil
}

type ValidatedTokenRequest struct {
	ClientID      string
	Nonce         string
	SessionHandle string
}

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

	// XXX: note the clientID is tied to the code via the AEAD cipher
	clientID := r.FormValue("client_id")
	if clientID == "" {
		return nil, &errorCodeError{
			errorCode:   "invalid_client",
			errorString: "missing client_id",
		}
	}

	grantType := r.FormValue("grant_type")
	if grantType != "authorization_code" {
		return nil, &errorCodeError{
			errorCode:   "unsupported_grant_type",
			errorString: fmt.Sprintf("unsupported grant type requested: %q", grantType),
		}
	}

	payload, err := h.codeEncryptor.Decrypt(r.FormValue("code"), clientID)
	if err != nil {
		return nil, fmt.Errorf("couldn't decrypt authorization code: %w", err)
	} else if payload.Expiration.Before(now) {
		return nil, fmt.Errorf("authorization code expired at %s",
			payload.Expiration.UTC().Format(timestampFormat))
	} else if u := r.FormValue("redirect_uri"); u != payload.RedirectURI {
		return nil, fmt.Errorf("unexpected redirect_uri provided, want %q, got %q", payload.RedirectURI, u)
	}

	verifier := r.FormValue("code_verifier")
	challenge := payload.S256CodeChallenge
	if verifier != "" || challenge != "" {
		hashed := sha256.Sum256([]byte(verifier))
		if challenge != base64.URLEncoding.EncodeToString(hashed[:]) {
			return nil, errors.New("incorrect code_verifier")
		}
	}

	return &ValidatedTokenRequest{
		ClientID:      clientID,
		Nonce:         payload.Nonce,
		SessionHandle: payload.SessionToken,
	}, nil
}

func validSession(data *handlers.UserInfoData) error {
	if data.Session == nil {
		return fmt.Errorf("no session")
	} else if _, ok := data.Session.GetClaims()["sub"]; !ok {
		return fmt.Errorf("missing subject")
	}
	return nil
}

func (h *Handlers) issueIDToken(data *handlers.UserInfoData, clientID string, nonce string) (string, error) {
	// Make sure we have a subject.
	if err := validSession(data); err != nil {
		return "", fmt.Errorf("can't issue ID token: %w", err)
	}

	payload := make(map[string]any)
	identity.CollectCommaSeparatedClaims(payload, data.User)
	identity.CollectCommaSeparatedClaims(payload, data.Session)

	// Rewrite "aud" and "iss".
	payload["aud"] = clientID
	payload["iss"] = h.issuerURL
	payload["iat"] = time.Now().Unix()
	payload["exp"] = time.Now().Add(1 * time.Hour).Unix() // XXX: how to set?
	if nonce != "" {
		payload["nonce"] = nonce
	}

	token, err := jwt.Signed(h.idTokenSigner).Claims(payload).CompactSerialize()
	if err != nil {
		return "", err
	}
	return token, nil
}

// HandleUserInfo handles a request to the user info endpoint.
func (h *Handlers) HandleUserInfo(w http.ResponseWriter, r *http.Request) {
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

	sh, err := h.parseSessionHandle(accessToken)
	if err != nil {
		log.Ctx(r.Context()).Info().Err(err).Msg("oidc: userinfo request couldn't parse session handle")
		(&JSONErrorResponse{
			Status: http.StatusInternalServerError,
			Error:  "server_error",
		}).serve(w, r)
		return
	}

	data := h.getUserInfoData(r, sh)

	payload := make(map[string]any)
	identity.CollectCommaSeparatedClaims(payload, data.User)
	identity.CollectCommaSeparatedClaims(payload, data.Session)
	delete(payload, "iss")
	delete(payload, "aud")
	delete(payload, "iat")
	delete(payload, "exp")

	serveJSON(w, payload)
}

func (h *Handlers) HandleJWKS(w http.ResponseWriter, _ *http.Request) {
	serveJSON(w, h.publicJWKS)
}

func serveJSON(w http.ResponseWriter, obj any) {
	bs, err := json.Marshal(obj)
	if err != nil {
		log.Error().Err(err).Msg("oidcprovider serveJSON() error")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// XXX: delete
	log.Info().Str("json", string(bs)).Msg("oidcprovider serveJSON()")

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(bs)
}

type errorCodeError struct { //nolint:errname
	status      int
	errorCode   string
	errorString string
}

func ToErrorCodeError(err error, defaultCode string) errorCodeError {
	if e, ok := errors.AsType[errorCodeError](err); ok {
		return e
	}
	return errorCodeError{
		errorCode:   defaultCode,
		errorString: err.Error(),
	}
}

func (e errorCodeError) Error() string {
	return e.errorCode + ": " + e.errorString
}

func (e errorCodeError) ServeJSON(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")

	bs, err := json.Marshal(map[string]string{
		"error":             e.errorCode,
		"error_description": e.errorString,
	})
	if err != nil {
		log.Ctx(r.Context()).Error().Err(err).Msg("JSONErrorResponse: couldn't marshal JSON")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"server_error"}`))
		return
	}

	w.WriteHeader(e.getStatus())
	_, _ = w.Write(bs)
}

func (e errorCodeError) getStatus() int {
	if e.status != 0 {
		return e.status
	}
	switch e.errorCode {
	case "invalid_client", "invalid_grant", "invalid_request":
		return http.StatusBadRequest
	case "invalid_token":
		return http.StatusUnauthorized
	case "server_error":
		return http.StatusInternalServerError
	}
	return http.StatusInternalServerError
}

func errorCodeOrDefault(err error, defaultErrorCode string) string {
	var e *errorCodeError
	if errors.As(err, &e) {
		return e.errorCode
	}
	return defaultErrorCode
}
