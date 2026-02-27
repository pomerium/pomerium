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
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"golang.org/x/oauth2"

	"github.com/pomerium/pomerium/internal/encoding"
)

type IDP struct {
	publicJWK  jose.JSONWebKey
	signingKey jose.SigningKey

	stateEncoder encoding.MarshalUnmarshaler
	userLookup   map[string]*User

	enableDeviceAuth bool

	// refresh token store
	refreshTokensMu sync.RWMutex
	refreshTokens   map[string]*refreshTokenData
}

// refreshTokenData stores the data associated with a refresh token.
type refreshTokenData struct {
	Email     string
	ClientID  string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

type Config struct {
	Users            []*User `json:"users"`
	EnableDeviceAuth bool    `json:"enable_device_auth"`
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
		refreshTokens:    make(map[string]*refreshTokenData),
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
		config := map[string]interface{}{
			"issuer":                 rootURL.String(),
			"authorization_endpoint": rootURL.ResolveReference(&url.URL{Path: "/oidc/auth"}).String(),
			"token_endpoint":         rootURL.ResolveReference(&url.URL{Path: "/oidc/token"}).String(),
			"jwks_uri":               rootURL.ResolveReference(&url.URL{Path: "/.well-known/jwks.json"}).String(),
			"userinfo_endpoint":      rootURL.ResolveReference(&url.URL{Path: "/oidc/userinfo"}).String(),
			"id_token_signing_alg_values_supported": []string{
				"ES256",
			},
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

	rawEmail := r.FormValue("email")
	if rawEmail != "" {
		http.Redirect(w, r, redirectURI.ResolveReference(&url.URL{
			RawQuery: (url.Values{
				"state": {r.FormValue("state")},
				"code": {state{
					Email:    rawEmail,
					ClientID: rawClientID,
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

	idp.serveToken(w, r, state)
}

// handleRefreshToken handles the refresh_token grant type.
func (idp *IDP) handleRefreshToken(w http.ResponseWriter, r *http.Request) {
	refreshToken := r.FormValue("refresh_token")
	if refreshToken == "" {
		http.Error(w, "missing refresh_token", http.StatusBadRequest)
		return
	}

	data, valid := idp.validateRefreshToken(refreshToken)
	if !valid {
		http.Error(w, "invalid or expired refresh_token", http.StatusUnauthorized)
		return
	}

	// Optionally validate client_id matches
	clientID := r.FormValue("client_id")
	if clientID != "" && clientID != data.ClientID {
		http.Error(w, "client_id mismatch", http.StatusUnauthorized)
		return
	}

	// Issue new tokens using the stored refresh token data
	idp.serveToken(w, r, &state{
		Email:    data.Email,
		ClientID: data.ClientID,
	})
}

// accessTokenExpiresIn is the lifetime of access tokens in seconds.
const accessTokenExpiresIn = 3600 // 1 hour

// refreshTokenLifetime is the lifetime of refresh tokens.
const refreshTokenLifetime = 30 * 24 * time.Hour // 30 days

func (idp *IDP) serveToken(w http.ResponseWriter, r *http.Request, state *state) {
	// Generate a new refresh token
	refreshToken := idp.createRefreshToken(state.Email, state.ClientID)

	serveJSON(w, map[string]interface{}{
		"access_token":  state.Encode(),
		"refresh_token": refreshToken,
		"token_type":    "Bearer",
		"expires_in":    accessTokenExpiresIn,
		"id_token":      state.GetIDToken(r, idp.userLookup).Encode(idp.signingKey),
	})
}

// createRefreshToken creates and stores a new refresh token.
func (idp *IDP) createRefreshToken(email, clientID string) string {
	token := uuid.NewString()
	now := time.Now()

	idp.refreshTokensMu.Lock()
	idp.refreshTokens[token] = &refreshTokenData{
		Email:     email,
		ClientID:  clientID,
		IssuedAt:  now,
		ExpiresAt: now.Add(refreshTokenLifetime),
	}
	idp.refreshTokensMu.Unlock()

	return token
}

// validateRefreshToken validates a refresh token and returns the associated data.
func (idp *IDP) validateRefreshToken(token string) (*refreshTokenData, bool) {
	idp.refreshTokensMu.RLock()
	data, ok := idp.refreshTokens[token]
	idp.refreshTokensMu.RUnlock()

	if !ok {
		return nil, false
	}

	if time.Now().After(data.ExpiresAt) {
		// Token expired, remove it
		idp.refreshTokensMu.Lock()
		delete(idp.refreshTokens, token)
		idp.refreshTokensMu.Unlock()
		return nil, false
	}

	return data, true
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

func serveJSON(w http.ResponseWriter, obj interface{}) {
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
	Email    string `json:"email"`
	ClientID string `json:"client_id"`
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
}

type idToken struct {
	*userInfo

	Issuer   string           `json:"iss"`
	Audience string           `json:"aud"`
	Expiry   *jwt.NumericDate `json:"exp"`
	IssuedAt *jwt.NumericDate `json:"iat"`
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

type User struct {
	ID        string `json:"-"`
	Email     string `json:"email"`
	FirstName string `json:"first_name,omitempty"`
	LastName  string `json:"last_name,omitempty"`
}
