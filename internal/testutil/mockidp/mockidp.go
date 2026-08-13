package mockidp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"golang.org/x/oauth2"

	"github.com/pomerium/pomerium/internal/encoding"
	"github.com/pomerium/pomerium/internal/oauth21"
)

// RotationMode selects how the mock IdP treats the presented refresh token on a
// refresh_token grant, matching the behaviors real IdPs implement.
type RotationMode int

const (
	// RotateKeepOld issues a new refresh token on every grant and keeps the
	// presented one valid forever (no invalidation). This is the historical
	// mockidp behavior and the default.
	RotateKeepOld RotationMode = iota
	// NonRotating returns the presented refresh token unchanged (no rotation).
	NonRotating
	// RotateInvalidate issues a new refresh token and invalidates the
	// presented one immediately (strict one-time-use).
	RotateInvalidate
	// RotateReuseDetect is RotateInvalidate plus reuse detection: presenting an
	// already-consumed token revokes the token's whole family, meaning every
	// outstanding token descended from the same grant, the way Auth0, Okta and
	// Entra treat replay as token theft.
	RotateReuseDetect
)

type IDP struct {
	publicJWK  jose.JSONWebKey
	signingKey jose.SigningKey

	stateEncoder encoding.MarshalUnmarshaler
	userLookup   map[string]*User

	enableDeviceAuth bool
	enablePKCE       bool

	rotationMode   RotationMode
	omitExpiresIn  bool
	accessTokenTTL time.Duration

	// refresh token store
	refreshTokensMu sync.RWMutex
	refreshTokens   map[string]*refreshTokenData
	// consumedTokens remembers tokens invalidated by rotation so
	// RotateReuseDetect can recognize a replay and revoke the token's family.
	consumedTokens map[string]*refreshTokenData

	// fault injection / test hooks, guarded by hooksMu.
	hooksMu           sync.Mutex
	refreshBarrier    func(refreshToken string)
	failRefreshStatus int
	failRefreshCount  int
	dropResponseCount int

	// refreshCount counts refresh_token grants, so tests can assert a user's
	// upstream session is refreshed once regardless of how many consumers
	// depend on it.
	refreshCount atomic.Int64
}

// RefreshCount returns the number of refresh_token grants served so far.
func (idp *IDP) RefreshCount() int64 { return idp.refreshCount.Load() }

// IssueRefreshToken mints a refresh token for a user, simulating the result of a
// completed login without driving the full browser flow.
func (idp *IDP) IssueRefreshToken(email, clientID string) string {
	return idp.createRefreshToken(email, clientID)
}

// AuthCode returns the authorization code this mock's /oidc/auth endpoint would
// issue for a user, so a test can run an auth-code exchange, and whatever that
// exchange warms up client-side, without a browser flow.
func (idp *IDP) AuthCode(email, clientID string) string {
	return state{Email: email, ClientID: clientID}.Encode()
}

// RevokeAllRefreshTokens invalidates every stored refresh token, simulating the
// user signing out at the IdP (subsequent refresh grants fail).
func (idp *IDP) RevokeAllRefreshTokens() {
	idp.refreshTokensMu.Lock()
	idp.refreshTokens = make(map[string]*refreshTokenData)
	idp.consumedTokens = make(map[string]*refreshTokenData)
	idp.refreshTokensMu.Unlock()
}

// IsRefreshTokenValid reports whether a refresh_token grant presenting this
// token would currently succeed.
func (idp *IDP) IsRefreshTokenValid(token string) bool {
	idp.refreshTokensMu.RLock()
	defer idp.refreshTokensMu.RUnlock()
	return validLocked(idp.refreshTokens[token])
}

// ValidRefreshTokenCount returns how many refresh tokens would currently be
// accepted by the token endpoint.
func (idp *IDP) ValidRefreshTokenCount() int {
	idp.refreshTokensMu.RLock()
	defer idp.refreshTokensMu.RUnlock()
	n := 0
	for _, data := range idp.refreshTokens {
		if validLocked(data) {
			n++
		}
	}
	return n
}

// validLocked is the single "would the token endpoint accept this?" rule.
// Callers must hold refreshTokensMu.
func validLocked(data *refreshTokenData) bool {
	return data != nil && !time.Now().After(data.ExpiresAt)
}

// SetRefreshBarrier installs a hook invoked at the start of every refresh_token
// grant, before any token state is touched. Tests use it to hold two concurrent
// refreshes in flight with the same token before either is processed. Pass nil
// to remove.
func (idp *IDP) SetRefreshBarrier(f func(refreshToken string)) {
	idp.hooksMu.Lock()
	idp.refreshBarrier = f
	idp.hooksMu.Unlock()
}

// FailNextRefresh makes the next n refresh_token grants fail with the given HTTP
// status before any token state is touched, simulating a transient IdP outage in
// which the presented token stays valid.
func (idp *IDP) FailNextRefresh(status, n int) {
	idp.hooksMu.Lock()
	idp.failRefreshStatus = status
	idp.failRefreshCount = n
	idp.hooksMu.Unlock()
}

// DropNextRefreshResponse makes the next n refresh_token grants execute fully at
// the IdP, consuming and rotating the presented token per the rotation mode, but
// replaces the response with a 502. This simulates the IdP performing the grant
// while the response never reaches the client, through a timeout, crash or
// network loss. The newly minted refresh token exists but is unknown to anyone.
func (idp *IDP) DropNextRefreshResponse(n int) {
	idp.hooksMu.Lock()
	idp.dropResponseCount = n
	idp.hooksMu.Unlock()
}

// refreshTokenData stores the data associated with a refresh token.
type refreshTokenData struct {
	Email    string
	ClientID string
	// Family identifies the grant lineage. The auth-code exchange mints a new
	// family and every rotation inherits it. Reuse detection revokes by family.
	Family    string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

type Config struct {
	Users            []*User `json:"users"`
	EnableDeviceAuth bool    `json:"enable_device_auth"`
	EnablePKCE       bool    `json:"enable_pkce"`

	// RotationMode selects the refresh-token rotation semantics. The zero
	// value (RotateKeepOld) preserves the historical mockidp behavior.
	RotationMode RotationMode `json:"-"`
	// OmitExpiresIn drops expires_in from token responses, like the providers
	// that leave the access token's lifetime unstated.
	OmitExpiresIn bool `json:"-"`
	// AccessTokenTTL overrides the access token lifetime reported as expires_in.
	// A short one lets a test reach the state where a stored token is due for
	// refresh in real time, rather than by moving a clock the store does not
	// measure ages against.
	AccessTokenTTL time.Duration `json:"-"`
}

func New(cfg Config) *IDP {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	publicKey := &privateKey.PublicKey

	signingKey := jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       privateKey,
	}
	publicJWK := jose.JSONWebKey{
		Key:       publicKey,
		Algorithm: string(jose.ES256),
		Use:       "sig",
	}
	thumbprint, err := publicJWK.Thumbprint(crypto.SHA256)
	if err != nil {
		panic(err)
	}
	publicJWK.KeyID = hex.EncodeToString(thumbprint)

	userLookup := map[string]*User{}
	for _, user := range cfg.Users {
		user.ID = uuid.NewString()
		userLookup[user.ID] = user
	}
	return &IDP{
		publicJWK:        publicJWK,
		signingKey:       signingKey,
		userLookup:       userLookup,
		enableDeviceAuth: cfg.EnableDeviceAuth,
		enablePKCE:       cfg.EnablePKCE,
		rotationMode:     cfg.RotationMode,
		omitExpiresIn:    cfg.OmitExpiresIn,
		accessTokenTTL:   cfg.AccessTokenTTL,
		refreshTokens:    make(map[string]*refreshTokenData),
		consumedTokens:   make(map[string]*refreshTokenData),
	}
}

func (idp *IDP) Start(t *testing.T) string {
	r := mux.NewRouter()
	idp.Register(r)
	server := httptest.NewServer(r)
	t.Cleanup(server.Close)
	return server.URL
}

func (idp *IDP) Register(router *mux.Router) {
	router.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(&jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{idp.publicJWK},
		})
	})
	router.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		rootURL := getRootURL(r)
		config := map[string]any{
			"issuer":                 rootURL.String(),
			"authorization_endpoint": rootURL.ResolveReference(&url.URL{Path: "/oidc/auth"}).String(),
			"token_endpoint":         rootURL.ResolveReference(&url.URL{Path: "/oidc/token"}).String(),
			"jwks_uri":               rootURL.ResolveReference(&url.URL{Path: "/.well-known/jwks.json"}).String(),
			"userinfo_endpoint":      rootURL.ResolveReference(&url.URL{Path: "/oidc/userinfo"}).String(),
			"id_token_signing_alg_values_supported": []string{
				"ES256",
			},
		}
		if idp.enablePKCE {
			config["code_challenge_methods_supported"] = []string{"S256"}
		}
		if idp.enableDeviceAuth {
			config["device_authorization_endpoint"] = rootURL.ResolveReference(&url.URL{Path: "/oidc/device/code"}).String()
		}
		_ = json.NewEncoder(w).Encode(config)
	})
	router.HandleFunc("/oidc/auth", idp.handleAuth)
	if idp.enableDeviceAuth {
		router.HandleFunc("/oidc/device/code", idp.handleDeviceCode)
	}
	router.HandleFunc("/oidc/token", idp.handleToken)
	router.HandleFunc("/oidc/userinfo", idp.handleUserInfo)
}

// handleAuth handles the auth flow for OIDC.
func (idp *IDP) handleAuth(w http.ResponseWriter, r *http.Request) {
	rawRedirectURI := r.FormValue("redirect_uri")
	if rawRedirectURI == "" {
		http.Error(w, "missing redirect_uri", http.StatusBadRequest)
		return
	}

	redirectURI, err := url.Parse(rawRedirectURI)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	rawClientID := r.FormValue("client_id")
	if rawClientID == "" {
		http.Error(w, "missing client_id", http.StatusBadRequest)
		return
	}

	codeChallenge := r.FormValue("code_challenge")
	codeChallengeMethod := r.FormValue("code_challenge_method")
	if idp.enablePKCE && codeChallenge == "" {
		http.Error(w, "missing code_challenge (PKCE required)", http.StatusBadRequest)
		return
	}

	rawEmail := r.FormValue("email")
	if rawEmail != "" {
		http.Redirect(w, r, redirectURI.ResolveReference(&url.URL{
			RawQuery: (url.Values{
				"state": {r.FormValue("state")},
				"code": {state{
					Email:               rawEmail,
					ClientID:            rawClientID,
					CodeChallenge:       codeChallenge,
					CodeChallengeMethod: codeChallengeMethod,
				}.Encode()},
			}).Encode(),
		}).String(), http.StatusFound)
		return
	}

	serveHTML(w, `<!doctype html>
	<html>
	<head>
		<title>Login</title>
	</head>
	<body>
		<form method="POST" style="max-width: 200px">
			<fieldset>
				<legend>Login</legend>

				<table>
					<tbody>
						<tr>
							<th><label for="email">Email</label></th>
							<td>
								<input type="email" name="email" placeholder="email" />
							</td>
						</tr>
						<tr>
							<td colspan="2">
								<input type="submit" />
							</td>
						</tr>
					</tbody>
				</table>

			</fieldset>
		</form>
	</body>
	</html>
	`)
}

// handleToken handles the token flow for OIDC.
func (idp *IDP) handleToken(w http.ResponseWriter, r *http.Request) {
	grantType := r.FormValue("grant_type")

	// Handle refresh token grant
	if grantType == "refresh_token" {
		idp.handleRefreshToken(w, r)
		return
	}

	// Handle device auth flow
	if idp.enableDeviceAuth && r.FormValue("device_code") != "" {
		idp.serveToken(w, r, &state{
			ClientID: r.FormValue("client_id"),
			Email:    "fake.user@example.com",
		})
		return
	}

	// Handle authorization code flow
	rawCode := r.FormValue("code")
	state, err := decodeState(rawCode)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if state.CodeChallenge != "" {
		codeVerifier := r.FormValue("code_verifier")
		if codeVerifier == "" {
			http.Error(w, "missing code_verifier", http.StatusBadRequest)
			return
		}
		valid := false
		switch state.CodeChallengeMethod {
		case "", "S256":
			valid = oauth21.VerifyPKCES256(codeVerifier, state.CodeChallenge)
		case "plain":
			valid = oauth21.VerifyPKCEPlain(codeVerifier, state.CodeChallenge)
		default:
			http.Error(w, "unsupported code_challenge_method", http.StatusBadRequest)
			return
		}
		if !valid {
			http.Error(w, "invalid code_verifier", http.StatusBadRequest)
			return
		}
	} else if r.FormValue("code_verifier") != "" {
		http.Error(w, "unexpected code_verifier", http.StatusBadRequest)
		return
	}

	idp.serveToken(w, r, state)
}

// handleRefreshToken handles the refresh_token grant type.
func (idp *IDP) handleRefreshToken(w http.ResponseWriter, r *http.Request) {
	idp.refreshCount.Add(1)
	refreshToken := r.FormValue("refresh_token")
	if refreshToken == "" {
		http.Error(w, "missing refresh_token", http.StatusBadRequest)
		return
	}

	// Test hook, letting concurrent refreshers meet before any state changes.
	idp.hooksMu.Lock()
	barrier := idp.refreshBarrier
	idp.hooksMu.Unlock()
	if barrier != nil {
		barrier(refreshToken)
	}

	// Fault injection: transient outage before any token state is touched.
	idp.hooksMu.Lock()
	if idp.failRefreshCount > 0 {
		idp.failRefreshCount--
		status := idp.failRefreshStatus
		idp.hooksMu.Unlock()
		http.Error(w, "temporarily unavailable", status)
		return
	}
	idp.hooksMu.Unlock()

	data, valid := idp.consumeRefreshToken(refreshToken)
	if !valid {
		// RFC 6749 §5.2 reports a refused grant as invalid_grant. Consumers
		// classify refresh failures by this code, and an opaque status would be
		// indistinguishable from an outage, so the mock returns it too.
		serveOAuthError(w, http.StatusBadRequest, oauth21.InvalidGrant, "invalid or expired refresh_token")
		return
	}

	// Optionally validate client_id matches
	clientID := r.FormValue("client_id")
	if clientID != "" && clientID != data.ClientID {
		http.Error(w, "client_id mismatch", http.StatusUnauthorized)
		return
	}

	idp.serveRefreshedToken(w, r, data, refreshToken)
}

// consumeRefreshToken validates the presented refresh token and applies the
// rotation mode's consumption rules. Concurrent presentations of the same
// one-time-use token are serialized here, so exactly one succeeds.
func (idp *IDP) consumeRefreshToken(token string) (*refreshTokenData, bool) {
	idp.refreshTokensMu.Lock()
	defer idp.refreshTokensMu.Unlock()

	data, ok := idp.refreshTokens[token]
	if !ok {
		// Reuse detection treats replaying a consumed token as theft and revokes
		// the whole family.
		if idp.rotationMode == RotateReuseDetect {
			if consumed, wasConsumed := idp.consumedTokens[token]; wasConsumed {
				idp.revokeFamilyLocked(consumed.Family)
			}
		}
		return nil, false
	}
	if !validLocked(data) {
		delete(idp.refreshTokens, token)
		return nil, false
	}

	switch idp.rotationMode {
	case NonRotating, RotateKeepOld:
		// presented token stays valid
	case RotateInvalidate, RotateReuseDetect:
		delete(idp.refreshTokens, token)
		consumed := *data
		idp.consumedTokens[token] = &consumed
	}
	return data, true
}

// revokeFamilyLocked deletes every valid and consumed token in a family.
// Callers must hold refreshTokensMu.
func (idp *IDP) revokeFamilyLocked(family string) {
	for tok, d := range idp.refreshTokens {
		if d.Family == family {
			delete(idp.refreshTokens, tok)
		}
	}
	for tok, d := range idp.consumedTokens {
		if d.Family == family {
			delete(idp.consumedTokens, tok)
		}
	}
}

// serveRefreshedToken responds to a successful refresh_token grant, minting the
// refresh token, or reusing it in NonRotating mode, per the rotation mode.
func (idp *IDP) serveRefreshedToken(w http.ResponseWriter, r *http.Request, data *refreshTokenData, presented string) {
	st := &state{Email: data.Email, ClientID: data.ClientID}

	refreshToken := presented
	if idp.rotationMode != NonRotating {
		refreshToken = idp.createRefreshTokenInFamily(data.Email, data.ClientID, data.Family)
	}

	// Fault injection: the grant executed and rotation happened, but the response
	// is lost. The client sees a 502, the old token is gone per the rotation
	// mode, and the new one is unknown to anyone.
	idp.hooksMu.Lock()
	if idp.dropResponseCount > 0 {
		idp.dropResponseCount--
		idp.hooksMu.Unlock()
		http.Error(w, "bad gateway (response lost in transit)", http.StatusBadGateway)
		return
	}
	idp.hooksMu.Unlock()

	serveJSON(w, idp.tokenResponse(st, refreshToken, st.GetIDToken(r, idp.userLookup).Encode(idp.signingKey)))
}

// tokenResponse builds a token endpoint response, leaving out expires_in when
// the mock is configured to omit it.
func (idp *IDP) tokenResponse(st *state, refreshToken, idToken string) map[string]any {
	res := map[string]any{
		"access_token":  st.Encode(),
		"refresh_token": refreshToken,
		"token_type":    "Bearer",
		"id_token":      idToken,
	}
	if !idp.omitExpiresIn {
		expiresIn := accessTokenExpiresIn
		if idp.accessTokenTTL > 0 {
			expiresIn = int(idp.accessTokenTTL.Seconds())
		}
		res["expires_in"] = expiresIn
	}
	return res
}

// accessTokenExpiresIn is the lifetime of access tokens in seconds.
const accessTokenExpiresIn = 3600 // 1 hour

// refreshTokenLifetime is the lifetime of refresh tokens.
const refreshTokenLifetime = 30 * 24 * time.Hour // 30 days

func (idp *IDP) serveToken(w http.ResponseWriter, r *http.Request, state *state) {
	// A fresh login (auth-code / device grant) starts a new token family.
	refreshToken := idp.createRefreshToken(state.Email, state.ClientID)

	serveJSON(w, idp.tokenResponse(state, refreshToken, state.GetIDToken(r, idp.userLookup).Encode(idp.signingKey)))
}

// createRefreshToken creates and stores a new refresh token in a new family, the
// result of a fresh grant such as an auth-code exchange.
func (idp *IDP) createRefreshToken(email, clientID string) string {
	return idp.createRefreshTokenInFamily(email, clientID, uuid.NewString())
}

// createRefreshTokenInFamily creates and stores a new refresh token descended
// from an existing grant family, the result of a rotation.
func (idp *IDP) createRefreshTokenInFamily(email, clientID, family string) string {
	token := uuid.NewString()
	now := time.Now()

	idp.refreshTokensMu.Lock()
	idp.refreshTokens[token] = &refreshTokenData{
		Email:     email,
		ClientID:  clientID,
		Family:    family,
		IssuedAt:  now,
		ExpiresAt: now.Add(refreshTokenLifetime),
	}
	idp.refreshTokensMu.Unlock()

	return token
}

// handleUserInfo handles retrieving the user info.
func (idp *IDP) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	authz := r.Header.Get("Authorization")
	if authz == "" {
		http.Error(w, "missing authorization header", http.StatusUnauthorized)
		return
	}

	if strings.HasPrefix(authz, "Bearer ") {
		authz = authz[len("Bearer "):]
	} else if strings.HasPrefix(authz, "token ") {
		authz = authz[len("token "):]
	} else {
		http.Error(w, "missing bearer token", http.StatusUnauthorized)
		return
	}

	state, err := decodeState(authz)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	serveJSON(w, state.GetUserInfo(idp.userLookup))
}

// handleDeviceCode initiates a device auth code flow.
//
// This is the bare minimum to simulate the device auth code flow. There is no client_id
// verification or any actual login.
func (idp *IDP) handleDeviceCode(w http.ResponseWriter, r *http.Request) {
	deviceCode := "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS"
	userCode := "ABCD-EFGH"

	rootURL := getRootURL(r)
	u := rootURL.ResolveReference(&url.URL{Path: "/oidc/device"}) // note: not actually implemented
	verificationURI := u.String()
	u.RawQuery = "user_code=" + userCode
	verificationURIComplete := u.String()

	serveJSON(w, &oauth2.DeviceAuthResponse{
		DeviceCode:              deviceCode,
		UserCode:                userCode,
		VerificationURI:         verificationURI,
		VerificationURIComplete: verificationURIComplete,
		Expiry:                  time.Now().Add(5 * time.Minute),
		Interval:                1,
	})
}

func getRootURL(r *http.Request) *url.URL {
	u := *r.URL
	if r.Host != "" {
		u.Host = r.Host
	}
	if u.Scheme == "" {
		if r.TLS != nil {
			u.Scheme = "https"
		} else {
			u.Scheme = "http"
		}
	}
	u.Path = ""
	return &u
}

func serveHTML(w http.ResponseWriter, html string) {
	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("Content-Length", strconv.Itoa(len(html)))
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, html)
}

// serveOAuthError writes an RFC 6749 §5.2 error response, using the same body
// shape Pomerium's own authorization server speaks.
func serveOAuthError(w http.ResponseWriter, status int, code oauth21.ErrorCode, description string) {
	bs, _ := json.Marshal(oauth21.Error{Code: code, Description: description})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(bs)
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

type state struct {
	Email               string `json:"email"`
	ClientID            string `json:"client_id"`
	CodeChallenge       string `json:"code_challenge,omitempty"`
	CodeChallengeMethod string `json:"code_challenge_method,omitempty"`
}

func decodeState(rawCode string) (*state, error) {
	var state state
	bs, _ := base64.URLEncoding.DecodeString(rawCode)
	err := json.Unmarshal(bs, &state)
	if err != nil {
		return nil, err
	}
	return &state, nil
}

func (state state) Encode() string {
	bs, _ := json.Marshal(state)
	return base64.URLEncoding.EncodeToString(bs)
}

func (state state) GetIDToken(r *http.Request, users map[string]*User) *idToken {
	token := &idToken{
		userInfo: state.GetUserInfo(users),

		Issuer:   getRootURL(r).String(),
		Audience: state.ClientID,
		Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour * 24 * 365)),
		IssuedAt: jwt.NewNumericDate(time.Now()),
	}
	return token
}

func (state state) GetUserInfo(users map[string]*User) *userInfo {
	userInfo := &userInfo{
		Subject: state.Email,
		Email:   state.Email,
	}

	for _, u := range users {
		if u.Email == state.Email {
			userInfo.Subject = u.ID
			userInfo.Name = strings.TrimSpace(u.FirstName + " " + u.LastName)
			userInfo.FamilyName = u.LastName
			userInfo.GivenName = u.FirstName
			userInfo.extra = u.Claims
		}
	}

	return userInfo
}

type userInfo struct {
	Subject    string `json:"sub"`
	Name       string `json:"name"`
	Email      string `json:"email"`
	FamilyName string `json:"family_name"`
	GivenName  string `json:"given_name"`

	// extra holds additional custom claims to merge into the JSON output.
	extra map[string]any
}

// claims returns the standard profile claims merged with any extra custom
// claims as top-level fields.
func (u *userInfo) claims() map[string]any {
	m := map[string]any{
		"sub":         u.Subject,
		"name":        u.Name,
		"email":       u.Email,
		"family_name": u.FamilyName,
		"given_name":  u.GivenName,
	}
	maps.Copy(m, u.extra)
	return m
}

// MarshalJSON renders the standard profile claims and merges in any extra
// custom claims as top-level fields.
func (u *userInfo) MarshalJSON() ([]byte, error) {
	return json.Marshal(u.claims())
}

type idToken struct {
	*userInfo

	Issuer   string           `json:"iss"`
	Audience string           `json:"aud"`
	Expiry   *jwt.NumericDate `json:"exp"`
	IssuedAt *jwt.NumericDate `json:"iat"`
}

// MarshalJSON merges the userinfo claims (including any custom claims) with the
// id_token's registered claims. It is defined explicitly because embedding
// *userInfo would otherwise promote userInfo.MarshalJSON and drop the
// iss/aud/exp/iat fields.
func (token *idToken) MarshalJSON() ([]byte, error) {
	m := token.userInfo.claims()
	m["iss"] = token.Issuer
	m["aud"] = token.Audience
	m["exp"] = token.Expiry
	m["iat"] = token.IssuedAt
	return json.Marshal(m)
}

func (token *idToken) Encode(signingKey jose.SigningKey) string {
	sig, err := jose.NewSigner(signingKey, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		panic(err)
	}

	str, err := jwt.Signed(sig).Claims(token).CompactSerialize()
	if err != nil {
		panic(err)
	}
	return str
}

// SignJWT signs an arbitrary claims payload with the IDP's signing key.
// Used by integration tests that need to mint JWTs outside of the OIDC flow
// (e.g. Kubernetes ServiceAccount-style tokens presented in the Authorization
// header).
func (idp *IDP) SignJWT(claims any) string {
	sig, err := jose.NewSigner(idp.signingKey, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		panic(err)
	}
	str, err := jwt.Signed(sig).Claims(claims).CompactSerialize()
	if err != nil {
		panic(err)
	}
	return str
}

type User struct {
	ID        string `json:"-"`
	Email     string `json:"email"`
	FirstName string `json:"first_name,omitempty"`
	LastName  string `json:"last_name,omitempty"`
	// Claims are additional claims to include in the id_token and the
	// userinfo response, beyond the standard profile claims above.
	Claims map[string]any `json:"claims,omitempty"`
}
