package oidcbridge

import (
	"crypto"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
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
	"github.com/pomerium/pomerium/internal/oauth21"
	"github.com/pomerium/pomerium/internal/oidcbridge/tokens"
	"github.com/pomerium/pomerium/pkg/endpoints"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/identity"
)

const nonceSizeLimit = 300 // not part of the OIDC spec

const idTokenValiditySeconds = 3600

type Handlers struct {
	issuerURL string

	codeEncryptor        *tokens.CodeEncryptor
	accessTokenEncryptor *tokens.AccessTokenEncryptor

	// map from client IDs to route details
	clients ClientLookup

	// key set for ID tokens that we sign
	publicJWKS jose.JSONWebKeySet

	idTokenSigner    jose.Signer
	getSessionHandle func(*http.Request) (*session.Handle, error)
	getUserInfoData  func(*http.Request, *session.Handle) handlers.UserInfoData
}

func NewHandlers(
	getSessionHandle func(*http.Request) (*session.Handle, error),
	getUserInfoData func(*http.Request, *session.Handle) handlers.UserInfoData,
	o *config.Options,
) (*Handlers, error) {
	h := &Handlers{
		issuerURL:        o.AuthenticateURLString,
		getSessionHandle: getSessionHandle,
		getUserInfoData:  getUserInfoData,
	}
	h.clients.buildForConfig(o)
	if h.clients.Empty() {
		return nil, nil
	}

	secret, err := o.GetSharedKey()
	if err != nil {
		return nil, err
	}
	aead, err := tokens.DeriveEncryptionCipher(secret)
	if err != nil {
		return nil, err
	}
	h.codeEncryptor = tokens.NewCodeEncryptor(aead)
	h.accessTokenEncryptor = tokens.NewAccessTokenEncryptor(aead)

	jwks, err := deriveJWKS(secret)
	if err != nil {
		return nil, err
	}
	h.idTokenSigner, err = jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: jwks.Keys[0]},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		return nil, err
	}

	h.publicJWKS.Keys = make([]jose.JSONWebKey, len(jwks.Keys))
	for i := range jwks.Keys {
		h.publicJWKS.Keys[i] = jwks.Keys[i].Public()
	}

	return h, nil
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

var oidcResponseTypesSupported = []string{"code"}

func (h *Handlers) HandleOIDCConfiguration(w http.ResponseWriter, r *http.Request) {
	var rootURL *url.URL
	rootURL, _ = url.Parse(h.issuerURL)
	config := map[string]any{
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
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
		"response_types_supported":              oidcResponseTypesSupported,
		"scopes_supported":                      oidcSupportedScopes,
	}
	serveJSON(w, r, config)
}

func (h *Handlers) HandleAuth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	validated, err := h.validateAuthRequest(r)
	if err != nil {
		// If the redirect_uri is not valid, we must not redirect to it.
		// See RFC 6749 §4.1.2.1.
		if validated == nil {
			(&httputil.HTTPError{
				Status:      http.StatusBadRequest,
				Description: err.Error(),
			}).ErrorResponse(r.Context(), w, r)
			return
		}
		e := &errorResponse{}
		if !errors.As(err, e) {
			e = &errorResponse{
				ErrorCode:   "invalid_request",
				Description: err.Error(),
			}
		}
		// Any other error should be redirected.
		http.Redirect(w, r, validated.ErrorRedirectURL(e), http.StatusFound)
		return
	}

	s, err := h.getSessionToken(r)
	if err != nil {
		log.Ctx(r.Context()).Error().Err(err).Msg("oidcbridge: could not retrieve session for auth request")
		e := &errorResponse{
			ErrorCode:   "server_error",
			Description: "could not retrieve session",
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

type validatedAuthRequest struct {
	ClientID          string
	RedirectURI       string
	State             string
	Nonce             string
	S256CodeChallenge string
}

func (h *Handlers) validateAuthRequest(r *http.Request) (*validatedAuthRequest, error) {
	client, err := h.clients.Lookup(r.FormValue("client_id"), r.FormValue("redirect_uri"))
	if err != nil {
		return nil, err
	}

	validated := &validatedAuthRequest{
		ClientID:    client.ID,
		RedirectURI: client.RedirectURI,
		State:       r.FormValue("state"),
	}

	if err := validateCodeResponseType(r.FormValue("response_type")); err != nil {
		return validated, err
	}

	// OIDC 3.1.2.6.
	//  This OP does not support use of the request parameter defined in Section 6.
	if r.FormValue("request") != "" {
		return validated, &errorResponse{ErrorCode: "request_not_supported"}
	}

	if scope := r.FormValue("scope"); !slices.Contains(oidcSupportedScopes, scope) {
		return validated, &errorResponse{
			ErrorCode:   "invalid_request",
			Description: fmt.Sprintf("unsupported scope requested : %s", scope),
		}
	}

	validated.S256CodeChallenge, err = validateCodeChallenge(
		r.FormValue("code_challenge_method"), r.FormValue("code_challenge"))
	if err != nil {
		return validated, err
	}

	// For a "public" client, a PKCE code challenge must be present.
	if client.SecretHash == nil && validated.S256CodeChallenge == "" {
		return validated, errors.New("code_challenge must be present for a public client")
	}

	nonce := r.FormValue("nonce")
	if len(nonce) > nonceSizeLimit {
		return validated, errors.New("nonce too large")
	}
	validated.Nonce = nonce

	return validated, nil
}

func (v *validatedAuthRequest) ErrorRedirectURL(e *errorResponse) string {
	q := url.Values{
		"error": {e.ErrorCode},
	}
	if e.Description != "" {
		q.Add("error_description", e.Description)
	}
	if v.State != "" {
		q.Add("state", v.State)
	}
	return v.RedirectURI + "?" + q.Encode()
}

func validateCodeChallenge(method, challenge string) (string, error) {
	switch method {
	case "":
		return "", nil
	case "S256":
		b, err := base64.RawURLEncoding.DecodeString(challenge)
		if err != nil || len(b) != sha256.Size {
			return "", errors.New("invalid code_challenge")
		}
		return challenge, nil
	default:
		return "", errors.New("unsupported code_challenge_method")
	}
}

func validateCodeResponseType(codeTypeRequested string) error {
	if !slices.Contains(oidcResponseTypesSupported, codeTypeRequested) {
		return oauth21.Error{
			Code:        oauth21.InvalidRequest,
			Description: fmt.Sprintf("code unsupported response_type: %s", codeTypeRequested),
		}
	}
	return nil
}

// HandleToken handles a token endpoint request, exchanging an authorization
// code for an access token and ID token. This endpoint is not user-facing, so
// errors are returned as JSON objects.
func (h *Handlers) HandleToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	req, err := h.validateTokenRequest(r, time.Now())
	if err != nil {
		log.Ctx(r.Context()).Info().Err(err).Msg("oidc: token request invalid")
		serveJSON(w, r, err)
		return
	}

	sh, err := h.parseSessionHandle(req.SessionHandle)
	if err != nil {
		log.Ctx(r.Context()).Info().Err(err).Msg("oidc: session handle parse error")
		serveJSON(w, r, &errorResponse{ErrorCode: "server_error"})
		return
	}

	data := h.getUserInfoData(r, sh)
	idToken, err := h.issueIDToken(&data, req.ClientID, req.Nonce)
	if err != nil {
		log.Ctx(r.Context()).Error().Err(err).Msg("oidc: couldn't issue ID token")
		serveJSON(w, r, &errorResponse{ErrorCode: "server_error"})
		return
	}

	resp := map[string]any{
		"access_token": h.accessTokenEncryptor.Encrypt(req.SessionHandle),
		"token_type":   "Bearer",
		"id_token":     idToken,
		"expires_in":   max(int(time.Until(data.Session.ExpiresAt.AsTime()).Seconds()), 0),
	}
	serveJSON(w, r, resp)
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

const timestampFormat = "2006-01-02 15:04:05 MST"

func (h *Handlers) validateTokenFormValues(r *http.Request) error {
	if err := r.ParseForm(); err != nil {
		return &errorResponse{
			ErrorCode: "invalid_request",
		}
	}
	// RFC 6749: The OAuth 2.0 Authorization Framework section §5.2, repeated values are not allowed
	for _, values := range r.Form {
		if len(values) > 1 {
			return &errorResponse{
				ErrorCode:   "invalid_request",
				Description: "repeated parameter",
			}
		}
	}
	if _, _, ok := r.BasicAuth(); ok {
		if _, ok := r.PostForm["client_secret"]; ok {
			return &errorResponse{
				ErrorCode:   "invalid_request",
				Description: "multiple client credentials",
			}
		}
	}
	if r.FormValue("redirect_uri") == "" {
		return &errorResponse{
			ErrorCode:   "invalid_request",
			Description: "missing redirect_uri",
		}
	}
	grantType := r.FormValue("grant_type")
	if grantType == "" {
		return &errorResponse{
			ErrorCode:   "invalid_request",
			Description: "missing grant_type",
		}
	}
	if r.FormValue("code") == "" {
		return &errorResponse{
			ErrorCode:   "invalid_request",
			Description: "missing code",
		}
	}
	return nil
}

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

	// Error codes are compliant with RFC 6749: The OAuth 2.0 Authorization Framework
	// section §5.2 & RFC 7636 PKCE by OAuth Public Clients sections §4.4.1 / §4.6.

	if err := h.validateTokenFormValues(r); err != nil {
		return nil, err
	}

	var clientID, clientSecret string
	if u, p, ok := r.BasicAuth(); ok {
		var err error
		clientID, err = url.QueryUnescape(u)
		if err != nil {
			return nil, newInvalidClientError("invalid client_secret_basic value")
		}
		clientSecret, err = url.QueryUnescape(p)
		if err != nil {
			return nil, newInvalidClientError("invalid client_secret_basic value")
		}
	} else {
		clientID = r.FormValue("client_id")
		clientSecret = r.FormValue("client_secret")
	}

	redirectURI := r.FormValue("redirect_uri")
	clientInfo, err := h.clients.Lookup(clientID, redirectURI)
	if err != nil {
		return nil, &errorResponse{
			ErrorCode:   "invalid_grant",
			Description: err.Error(),
		}
	}

	// Currently only the authorization_code grant is supported.
	grantType := r.FormValue("grant_type")
	if grantType != "authorization_code" {
		return nil, &errorResponse{
			ErrorCode:   "unsupported_grant_type",
			Description: fmt.Sprintf("grant type %s is not supported", grantType),
		}
	}

	payload, err := h.codeEncryptor.Decrypt(r.FormValue("code"), clientID)
	if err != nil {
		return nil, &errorResponse{
			ErrorCode:   "invalid_grant",
			Description: "invalid authorization code",
		}
	} else if payload.Expiration.Before(now) {
		return nil, &errorResponse{
			ErrorCode: "invalid_grant",
			Description: fmt.Sprintf("authorization code expired at %s",
				payload.Expiration.UTC().Format(timestampFormat)),
		}
	} else if redirectURI != payload.RedirectURI {
		return nil, &errorResponse{
			ErrorCode:   "invalid_grant",
			Description: "incorrect or missing redirect_uri",
		}
	}

	// If the client has a registered client_secret, the incoming request must
	// present it.
	if clientInfo.SecretHash != nil {
		hash := sha256.Sum256([]byte(clientSecret))
		if subtle.ConstantTimeCompare(hash[:], clientInfo.SecretHash) != 1 {
			return nil, newInvalidClientError("incorrect client_secret")
		}
	}

	// Verify PKCE challenge.
	verifier := r.FormValue("code_verifier")
	challenge := payload.S256CodeChallenge
	if verifier != "" || challenge != "" {
		if !oauth21.VerifyPKCES256(verifier, challenge) {
			// RFC 7636 §4.6
			return nil, &errorResponse{
				ErrorCode:   "invalid_grant",
				Description: "incorrect code_verifier",
			}
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
		return fmt.Errorf("missing session")
	} else if err := data.Session.Validate(); err != nil {
		return err
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
	identity.CollectClaims(payload, data.User)
	identity.CollectClaims(payload, data.Session)
	// "Normalizing" claims by scope is not technically required for strict conformance,
	// but is probably better practice here. The OIDC conformance suite also flags
	// this as best practice.
	// Note that it is by design that the user info endpoint doesn't normalize scopes yet.
	NormalizeClaimsByScope(payload, scopeClaimsOIDC)

	// Make sure "aud" and "iss" refer to the OIDC flow between Pomerium and the
	// upstream application, not the underlying IdP and Pomerium.
	payload["aud"] = clientID
	payload["iss"] = h.issuerURL
	iat := time.Now().Unix()
	payload["iat"] = iat
	payload["exp"] = iat + idTokenValiditySeconds
	if nonce != "" {
		payload["nonce"] = nonce
	} else {
		delete(payload, "nonce")
	}

	token, err := jwt.Signed(h.idTokenSigner).Claims(payload).CompactSerialize()
	if err != nil {
		return "", err
	}
	return token, nil
}

// HandleUserInfo handles a request to the user info endpoint.
// As detailed in the RFC, returning claims per scope requested is out of scope
// for the current implementation.
func (h *Handlers) HandleUserInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	// From RFC 6750 Bearer Token Usage §3.1

	//    When a request fails, the resource server responds using the
	//    appropriate HTTP status code (typically, 400, 401, 403, or 405) and
	//    includes one of the following error codes in the response:

	//    invalid_request
	//          The request is missing a required parameter, includes an
	//          unsupported parameter or parameter value, repeats the same
	//          parameter, uses more than one method for including an access
	//          token, or is otherwise malformed.  The resource server SHOULD
	//          respond with the HTTP 400 (Bad Request) status code.

	//    invalid_token
	//          The access token provided is expired, revoked, malformed, or
	//          invalid for other reasons.  The resource SHOULD respond with
	//          the HTTP 401 (Unauthorized) status code.  The client MAY
	//          request a new access token and retry the protected resource
	//          request.

	//    insufficient_scope
	//          The request requires higher privileges than provided by the
	//          access token.  The resource server SHOULD respond with the HTTP
	//          403 (Forbidden) status code and MAY include the "scope"
	//          attribute with the scope necessary to access the protected
	//          resource.

	if err := r.ParseForm(); err != nil {
		serveJSON(w, r, &errorResponse{ErrorCode: "invalid_request"})
		return
	}
	bearerToken, hasHeader := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	bodyToken := r.PostForm.Get("access_token")
	if hasHeader && bodyToken != "" {
		serveJSON(w, r, &errorResponse{ErrorCode: "invalid_request"})
		return
	}
	authz := bearerToken
	if bodyToken != "" {
		authz = bodyToken
	}
	log.Ctx(r.Context()).Debug()
	if authz == "" {
		log.Ctx(r.Context()).Info().Msg("oidc: userinfo request missing access token")
		serveJSON(w, r, &errorResponse{ErrorCode: "invalid_request"})
		return
	}

	accessToken, err := h.accessTokenEncryptor.Decrypt(authz)
	if err != nil {
		log.Ctx(r.Context()).Info().Err(err).Msg("oidc: userinfo request has invalid access token")
		serveJSON(w, r, &errorResponse{ErrorCode: "invalid_token"})
		return
	}

	sh, err := h.parseSessionHandle(accessToken)
	if err != nil {
		log.Ctx(r.Context()).Info().Err(err).Msg("oidc: userinfo request couldn't parse session handle")
		serveJSON(w, r, &errorResponse{ErrorCode: "server_error"})
		return
	}

	data := h.getUserInfoData(r, sh)
	if err := validSession(&data); err != nil {
		log.Ctx(r.Context()).Info().Msg("oidc: userinfo request has invalid session")
		serveJSON(w, r, &errorResponse{ErrorCode: "invalid_token"})
		return
	}

	payload := make(map[string]any)
	identity.CollectClaims(payload, data.User)
	identity.CollectClaims(payload, data.Session)
	for _, k := range []string{"iss", "aud", "azp", "nonce", "iat", "exp"} {
		delete(payload, k)
	}

	serveJSON(w, r, payload)
}

func (h *Handlers) HandleJWKS(w http.ResponseWriter, r *http.Request) {
	serveJSON(w, r, h.publicJWKS)
}

func serveJSON(w http.ResponseWriter, r *http.Request, obj any) {
	w.Header().Set("Content-Type", "application/json")

	bs, err := json.Marshal(obj)
	if err != nil {
		log.Ctx(r.Context()).Error().Err(err).Msg("oidcbridge.errorResponse: couldn't marshal JSON")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"server_error"}`))
		return
	}

	if h, ok := obj.(interface{ GetHTTPHeaders() map[string]string }); ok {
		for k, v := range h.GetHTTPHeaders() {
			w.Header().Add(k, v)
		}
	}

	if s, ok := obj.(interface{ GetHTTPStatus() int }); ok {
		if status := s.GetHTTPStatus(); status != 0 {
			w.WriteHeader(status)
		}
	}
	_, _ = w.Write(bs)
}

type errorResponse struct {
	Status      int               `json:"-"`
	Headers     map[string]string `json:"-"`
	ErrorCode   string            `json:"error"`
	Description string            `json:"error_description,omitempty"`
}

func newInvalidClientError(description string) *errorResponse {
	return &errorResponse{
		Headers: map[string]string{
			"WWW-Authenticate": `Basic realm="oidc"`,
		},
		ErrorCode:   "invalid_client",
		Description: description,
	}
}

func (e errorResponse) Error() string {
	if e.Description != "" {
		return e.ErrorCode + ": " + e.Description
	}
	return e.ErrorCode
}

func (e *errorResponse) GetHTTPStatus() int {
	if e.Status != 0 {
		return e.Status
	}
	switch e.ErrorCode {
	case "invalid_client":
		return http.StatusUnauthorized
	case "invalid_grant", "invalid_request", "unsupported_grant_type":
		return http.StatusBadRequest
	case "invalid_token":
		return http.StatusUnauthorized
	default:
		return http.StatusInternalServerError
	}
}

func (e *errorResponse) GetHTTPHeaders() map[string]string {
	return e.Headers
}

type OIDCScope string

const (
	scopeClaimsOIDC OIDCScope = "openid"
)

var (
	oidcSupportedScopes = []string{
		string(scopeClaimsOIDC),
	}
	claimsOIDCScope = []string{
		"aud", "exp", "iat", "iss", "sid", "sub",
	}
)

func NormalizeClaimsByScope(claims map[string]any, scope OIDCScope) {
	filter := []string{}
	switch scope {
	case scopeClaimsOIDC:
		filter = claimsOIDCScope
	}

	for k := range claims {
		if !slices.Contains(filter, k) {
			delete(claims, k)
		}
	}
}
