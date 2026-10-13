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
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strconv"
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
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/identity"
)

const nonceSizeLimit = 300 // not part of the OIDC spec

const idTokenValiditySeconds = 3600

// upstreamTokenClaims are claims that the upstream IdP's ID token carries about
// that token itself (its ID, validity, hashes of artifacts issued alongside it,
// the IdP session it belongs to). They do not describe the end user, and are
// meaningless or wrong in a token we issue.
var upstreamTokenClaims = []string{
	// Defined by JWT (RFC 7519) and OIDC Core.
	"aud", "azp", "exp", "iat", "iss", "jti", "nbf", "nonce",
	"at_hash", "c_hash", "s_hash", "sid",
	// IdP-specific, seen from Keycloak. Other IdPs have their own.
	"session_state", "typ",
}

// collectUserClaims returns the claims about the end user from the session and
// user records.
func collectUserClaims(data *handlers.UserInfoData) map[string]any {
	claims := make(map[string]any)
	identity.CollectClaims(claims, data.User)
	identity.CollectClaims(claims, data.Session)
	for _, k := range upstreamTokenClaims {
		delete(claims, k)
	}
	return claims
}

type Handlers struct {
	issuerURL string

	codeEncryptor        *tokens.CodeEncryptor
	accessTokenEncryptor *tokens.AccessTokenEncryptor

	// map from client IDs to route details
	clients ClientLookup

	// key set for ID tokens that we sign
	publicJWKS jose.JSONWebKeySet

	idTokenSigner   jose.Signer
	getUserInfoData func(*http.Request, *session.Handle) handlers.UserInfoData

	// records redeemed authorization codes, which makes codes single-use
	dataBrokerClient databroker.DataBrokerServiceClient
}

// SessionAuthenticator gives the authorization endpoint access to the end
// user's Pomerium session. The authenticate service implements it.
type SessionAuthenticator interface {
	// VerifiedSessionHandle returns the handle of the request's Pomerium
	// session, or an error if the request has no valid session.
	VerifiedSessionHandle(r *http.Request) (*session.Handle, error)
	// Reauthenticate signs the user in with the identity provider again and
	// then returns them to r.URL. idpParams are added to the identity
	// provider's authorization request.
	Reauthenticate(w http.ResponseWriter, r *http.Request, idpParams url.Values) error
}

// NewHandlers returns the bridge's handlers, or nil if no route enables it.
// Authorization codes are single-use only with a dataBrokerClient.
func NewHandlers(
	getUserInfoData func(*http.Request, *session.Handle) handlers.UserInfoData,
	dataBrokerClient databroker.DataBrokerServiceClient,
	o *config.Options,
) (*Handlers, error) {
	h := &Handlers{
		issuerURL:        o.AuthenticateURLString,
		getUserInfoData:  getUserInfoData,
		dataBrokerClient: dataBrokerClient,
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
		"response_types_supported":              []string{"code"},
		"response_modes_supported":              []string{"query"},
		"scopes_supported":                      []string{"openid"},
		"prompt_values_supported":               []string{"none", "login"},
		// Not exhaustive (which the spec allows): the remaining claims are
		// whatever the identity provider supplies.
		"claims_supported": []string{"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce"},
		// Request objects are not supported. The default for
		// request_uri_parameter_supported is true, so say so explicitly.
		"request_parameter_supported":     false,
		"request_uri_parameter_supported": false,
	}
	serveJSON(w, r, config)
}

// HandleAuth handles an authorization endpoint request (GET or POST).
func (h *Handlers) HandleAuth(w http.ResponseWriter, r *http.Request, sessions SessionAuthenticator) {
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

		// Any other error should be redirected.
		http.Redirect(w, r, validated.ErrorRedirectURL(asErrorResponse(err)), http.StatusFound)
		return
	}

	sh := h.authenticatedSession(r, validated, sessions)
	if sh == nil {
		signIn(w, r, validated, sessions)
		return
	}

	s, err := encodeSessionHandle(sh)
	if err != nil {
		log.Ctx(r.Context()).Error().Err(err).Msg("oidcbridge: could not encode session for auth request")
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
		Nonce:             validated.Nonce,
		SessionToken:      s,
	}, validated.ClientID))
	q.Set("state", validated.State)
	http.Redirect(w, r, validated.RedirectURI+"?"+q.Encode(), http.StatusFound)
}

// authenticatedSession returns the session to issue an authorization code for,
// or nil if the user must sign in (again) first.
func (h *Handlers) authenticatedSession(
	r *http.Request, validated *validatedAuthRequest, sessions SessionAuthenticator,
) *session.Handle {
	if validated.PromptLogin {
		return nil
	}
	sh, err := sessions.VerifiedSessionHandle(r)
	if err != nil {
		return nil
	}
	if validated.MaxAge != nil {
		data := h.getUserInfoData(r, sh)
		if time.Since(authTime(&data)) > *validated.MaxAge {
			return nil
		}
	}
	return sh
}

// signIn sends the user to sign in with the identity provider, after which the
// authorization request continues. With prompt=none the client gets
// login_required instead (OIDC Core §3.1.2.6).
func signIn(w http.ResponseWriter, r *http.Request, validated *validatedAuthRequest, sessions SessionAuthenticator) {
	if validated.PromptNone {
		http.Redirect(w, r, validated.ErrorRedirectURL(&errorResponse{ErrorCode: "login_required"}), http.StatusFound)
		return
	}

	// Continue with the same request (as a GET, in case this one was a POST),
	// minus what signing in satisfies (prompt=login and max_age), so that it
	// is not requested again.
	continueParams := maps.Clone(r.Form)
	continueParams.Del("max_age")
	prompt := slices.DeleteFunc(strings.Fields(continueParams.Get("prompt")), func(v string) bool {
		return v == "login"
	})
	if len(prompt) > 0 {
		continueParams.Set("prompt", strings.Join(prompt, " "))
	} else {
		continueParams.Del("prompt")
	}
	continueURL := *r.URL
	continueURL.RawQuery = continueParams.Encode()
	r = r.Clone(r.Context())
	r.Method = http.MethodGet
	r.URL = &continueURL
	r.Body = http.NoBody

	httputil.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return sessions.Reauthenticate(w, r, validated.idpParams())
	}).ServeHTTP(w, r)
}

// authTime returns when the user last authenticated: the identity provider's
// auth_time if it reported one, otherwise when the Pomerium session started.
func authTime(data *handlers.UserInfoData) time.Time {
	if lv := data.Session.GetClaims()["auth_time"]; len(lv.GetValues()) == 1 {
		if v, ok := lv.GetValues()[0].AsInterface().(float64); ok {
			return time.Unix(int64(v), 0)
		}
	}
	return data.Session.GetIssuedAt().AsTime()
}

func encodeSessionHandle(s *session.Handle) (string, error) {
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

	PromptNone  bool
	PromptLogin bool
	// MaxAge is the max_age parameter, if present.
	MaxAge *time.Duration
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

	switch responseType := r.FormValue("response_type"); responseType {
	case "code":
	case "":
		return validated, errors.New("missing response_type")
	default:
		return validated, &errorResponse{
			ErrorCode:   "unsupported_response_type",
			Description: fmt.Sprintf("response_type %q is not supported", responseType),
		}
	}
	if m := r.FormValue("response_mode"); m != "" && m != "query" {
		return validated, fmt.Errorf("unsupported response_mode %q", m)
	}

	// Request objects are not supported (OIDC Core §6). Ignoring them would
	// ignore the parameters inside them.
	if r.Form.Has("request") {
		return validated, &errorResponse{ErrorCode: "request_not_supported"}
	}
	if r.Form.Has("request_uri") {
		return validated, &errorResponse{ErrorCode: "request_uri_not_supported"}
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

	// prompt is a space-delimited list (OIDC Core §3.1.2.1).
	prompt := strings.Fields(r.FormValue("prompt"))
	validated.PromptNone = slices.Contains(prompt, "none")
	validated.PromptLogin = slices.Contains(prompt, "login")
	if validated.PromptNone && len(prompt) > 1 {
		return validated, errors.New(`prompt "none" cannot be combined with other values`)
	}

	if v := r.FormValue("max_age"); v != "" {
		seconds, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return validated, fmt.Errorf("invalid max_age %q", v)
		}
		validated.MaxAge = new(time.Duration(seconds) * time.Second)
	}

	return validated, nil
}

// idpParams returns the parameters to pass on to the identity provider when
// the user signs in, so that it also re-authenticates them as requested.
func (v *validatedAuthRequest) idpParams() url.Values {
	params := url.Values{}
	if v.PromptLogin {
		params.Set("prompt", "login")
	}
	if v.MaxAge != nil {
		params.Set("max_age", strconv.FormatInt(int64(v.MaxAge.Seconds()), 10))
	}
	return params
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
		return "", fmt.Errorf("unsupported code_challenge_method %q", method)
	}
}

// HandleToken handles a token endpoint request, exchanging an authorization
// code for an access token and ID token. This endpoint is not user-facing, so
// errors are returned as JSON objects.
func (h *Handlers) HandleToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	req, err := h.validateTokenRequest(r, time.Now())
	if err == nil {
		// Only now, with the request otherwise valid, use up the code: a
		// request that fails validation must not burn it.
		err = h.redeemCode(r.Context(), req)
	}
	var errResp *errorResponse
	if errors.As(err, &errResp) {
		log.Ctx(r.Context()).Info().Err(err).Msg("oidc: token request invalid")
		serveJSON(w, r, errResp)
		return
	} else if err != nil {
		log.Ctx(r.Context()).Error().Err(err).Msg("oidc: couldn't validate token request")
		serveJSON(w, r, &errorResponse{ErrorCode: "server_error"})
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
		"access_token": h.accessTokenEncryptor.Encrypt(&tokens.AccessTokenPayload{
			CodeID:       req.CodeID,
			SessionToken: req.SessionHandle,
		}),
		"token_type": "Bearer",
		"id_token":   idToken,
		"expires_in": max(int(time.Until(data.Session.ExpiresAt.AsTime()).Seconds()), 0),
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
	ClientID       string
	CodeID         string
	CodeExpiration time.Time
	Nonce          string
	SessionHandle  string
}

const timestampFormat = "2006-01-02 15:04:05 MST"

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
	//  - (4) needs the databroker; HandleToken calls redeemCode afterwards.
	//  - Error codes follow RFC 6749 §5.2: failed client authentication is
	//    invalid_client, and any problem with the code is invalid_grant.

	var clientID, clientSecret string
	u, p, usedBasicAuth := r.BasicAuth()
	if usedBasicAuth {
		var err error
		clientID, err = url.QueryUnescape(u)
		if err != nil {
			return nil, &errorResponse{
				ErrorCode:   "invalid_request",
				Description: "invalid client_secret_basic value",
			}
		}
		clientSecret, err = url.QueryUnescape(p)
		if err != nil {
			return nil, &errorResponse{
				ErrorCode:   "invalid_request",
				Description: "invalid client_secret_basic value",
			}
		}
	} else {
		clientID = r.FormValue("client_id")
		clientSecret = r.FormValue("client_secret")
	}
	clientInfo, err := h.clients.LookupClient(clientID)
	if err != nil {
		return nil, invalidClient(usedBasicAuth, err.Error())
	}

	// If the client has a registered client_secret, the incoming request must
	// present it.
	if clientInfo.SecretHash != nil {
		hash := sha256.Sum256([]byte(clientSecret))
		if subtle.ConstantTimeCompare(hash[:], clientInfo.SecretHash) != 1 {
			return nil, invalidClient(usedBasicAuth, "incorrect client_secret")
		}
	}

	// Currently only the authorization_code grant is supported.
	grantType := r.FormValue("grant_type")
	if grantType != "authorization_code" {
		return nil, &errorResponse{
			ErrorCode:   "unsupported_grant_type",
			Description: fmt.Sprintf("grant type %q is not supported", grantType),
		}
	}

	code := r.FormValue("code")
	payload, err := h.codeEncryptor.Decrypt(code, clientID)
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
	} else if u := r.FormValue("redirect_uri"); u != payload.RedirectURI {
		return nil, &errorResponse{
			ErrorCode:   "invalid_grant",
			Description: "incorrect or missing redirect_uri",
		}
	}

	// Verify PKCE challenge.
	verifier := r.FormValue("code_verifier")
	challenge := payload.S256CodeChallenge
	if verifier != "" || challenge != "" {
		if !oauth21.VerifyPKCES256(verifier, challenge) {
			return nil, &errorResponse{
				ErrorCode:   "invalid_grant",
				Description: "incorrect code_verifier",
			}
		}
	}

	return &ValidatedTokenRequest{
		ClientID:       clientID,
		CodeID:         codeID(code),
		CodeExpiration: payload.Expiration,
		Nonce:          payload.Nonce,
		SessionHandle:  payload.SessionToken,
	}, nil
}

// invalidClient returns the error for failed client authentication. A client
// that authenticated with HTTP Basic gets a matching challenge (RFC 6749 §5.2).
func invalidClient(usedBasicAuth bool, description string) *errorResponse {
	e := &errorResponse{
		ErrorCode:   "invalid_client",
		Description: description,
	}
	if usedBasicAuth {
		e.Challenge = `Basic realm="token"`
	}
	return e
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

	payload := collectUserClaims(data)

	// Make sure "aud" and "iss" refer to the OIDC flow between Pomerium and the
	// upstream application, not the underlying IdP and Pomerium.
	payload["aud"] = clientID
	payload["iss"] = h.issuerURL
	iat := time.Now().Unix()
	payload["iat"] = iat
	payload["exp"] = iat + idTokenValiditySeconds
	if nonce != "" {
		payload["nonce"] = nonce
	}
	// Required when the request had max_age (OIDC Core §2), which the client
	// may not repeat at the token endpoint, so always include it.
	if t := authTime(data); t.Unix() > 0 {
		payload["auth_time"] = t.Unix()
	}

	token, err := jwt.Signed(h.idTokenSigner).Claims(payload).CompactSerialize()
	if err != nil {
		return "", err
	}
	return token, nil
}

// HandleUserInfo handles a request to the user info endpoint (GET or POST).
func (h *Handlers) HandleUserInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	token, err := requestAccessToken(r)
	if err != nil {
		log.Ctx(r.Context()).Info().Err(err).Msg("oidc: userinfo request has no usable access token")
		serveJSON(w, r, &errorResponse{ErrorCode: "invalid_request"})
		return
	}

	accessToken, err := h.accessTokenEncryptor.Decrypt(token)
	if err != nil {
		log.Ctx(r.Context()).Info().Err(err).Msg("oidc: userinfo request has invalid access token")
		serveJSON(w, r, invalidToken())
		return
	}

	if revoked, err := h.codeRevoked(r.Context(), accessToken.CodeID); err != nil {
		log.Ctx(r.Context()).Error().Err(err).Msg("oidc: userinfo request couldn't check token revocation")
		serveJSON(w, r, &errorResponse{ErrorCode: "server_error"})
		return
	} else if revoked {
		log.Ctx(r.Context()).Info().Msg("oidc: userinfo request has a revoked access token")
		serveJSON(w, r, invalidToken())
		return
	}

	sh, err := h.parseSessionHandle(accessToken.SessionToken)
	if err != nil {
		log.Ctx(r.Context()).Info().Err(err).Msg("oidc: userinfo request couldn't parse session handle")
		serveJSON(w, r, &errorResponse{ErrorCode: "server_error"})
		return
	}

	data := h.getUserInfoData(r, sh)
	if err := validSession(&data); err != nil {
		log.Ctx(r.Context()).Info().Msg("oidc: userinfo request has invalid session")
		serveJSON(w, r, invalidToken())
		return
	}

	serveJSON(w, r, collectUserClaims(&data))
}

// requestAccessToken returns the access token from the Authorization header
// or, with POST, from a form-encoded body, but not both (RFC 6750 §2).
func requestAccessToken(r *http.Request) (string, error) {
	authz := r.Header.Get("Authorization")
	var bodyToken string
	if r.Method == http.MethodPost {
		bodyToken = r.PostFormValue("access_token")
	}
	switch {
	case authz != "" && bodyToken != "":
		return "", errors.New("more than one access token")
	case authz != "":
		token, ok := strings.CutPrefix(authz, "Bearer ")
		if !ok {
			return "", errors.New("authorization header is not a bearer token")
		}
		return token, nil
	case bodyToken != "":
		return bodyToken, nil
	default:
		return "", errors.New("missing access token")
	}
}

// invalidToken returns the error for an unusable access token, with the
// challenge that RFC 6750 §3 requires.
func invalidToken() *errorResponse {
	return &errorResponse{
		ErrorCode: "invalid_token",
		Challenge: `Bearer error="invalid_token"`,
	}
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

	if e, ok := obj.(*errorResponse); ok && e.Challenge != "" {
		w.Header().Set("WWW-Authenticate", e.Challenge)
	}
	if s, ok := obj.(interface{ GetHTTPStatus() int }); ok {
		if status := s.GetHTTPStatus(); status != 0 {
			w.WriteHeader(status)
		}
	}
	_, _ = w.Write(bs)
}

type errorResponse struct {
	Status      int    `json:"-"`
	ErrorCode   string `json:"error"`
	Description string `json:"error_description,omitempty"`
	// Challenge is the WWW-Authenticate header value, if any.
	Challenge string `json:"-"`
}

// asErrorResponse returns err as an errorResponse: as is if it is one, and as
// invalid_request otherwise.
func asErrorResponse(err error) *errorResponse {
	var e *errorResponse
	if errors.As(err, &e) {
		return e
	}
	return &errorResponse{ErrorCode: "invalid_request", Description: err.Error()}
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
	case "invalid_grant", "invalid_request", "unsupported_grant_type":
		return http.StatusBadRequest
	case "invalid_client", "invalid_token":
		return http.StatusUnauthorized
	default:
		return http.StatusInternalServerError
	}
}
