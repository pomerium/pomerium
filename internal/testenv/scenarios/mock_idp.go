package scenarios

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/oauth2"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/google/uuid"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/encoding"
	"github.com/pomerium/pomerium/internal/encoding/jws"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/testenv"
	"github.com/pomerium/pomerium/internal/testenv/upstreams"
	"github.com/pomerium/pomerium/internal/testenv/values"
	"github.com/pomerium/pomerium/pkg/grpc/identity"
)

type IDP struct {
	IDPOptions
	id         values.Value[string]
	url        values.Value[string]
	publicJWK  jose.JSONWebKey
	signingKey jose.SigningKey

	stateEncoder encoding.MarshalUnmarshaler
	userLookup   map[string]*User
}

type IDPOptions struct {
	enableTLS        bool
	enableDeviceAuth bool
}

type IDPOption func(*IDPOptions)

func (o *IDPOptions) apply(opts ...IDPOption) {
	for _, op := range opts {
		op(o)
	}
}

func WithEnableTLS(enableTLS bool) IDPOption {
	return func(o *IDPOptions) {
		o.enableTLS = enableTLS
	}
}

func WithEnableDeviceAuth(enableDeviceAuth bool) IDPOption {
	return func(o *IDPOptions) {
		o.enableDeviceAuth = enableDeviceAuth
	}
}

// Attach implements testenv.Modifier.
func (idp *IDP) Attach(ctx context.Context) {
	env := testenv.EnvFromContext(ctx)

	idpURL := env.SubdomainURL("mock-idp")

	var tlsConfig values.Value[*tls.Config]
	if idp.enableTLS {
		tlsConfig = values.Bind(idpURL, func(urlStr string) *tls.Config {
			u, _ := url.Parse(urlStr)
			cert := env.NewServerCert(&x509.Certificate{
				DNSNames: []string{u.Hostname()},
			})
			return &tls.Config{
				RootCAs:      env.ServerCAs(),
				Certificates: []tls.Certificate{tls.Certificate(*cert)},
				NextProtos:   []string{"http/1.1", "h2"},
			}
		})
	}

	router := upstreams.HTTP(tlsConfig, upstreams.WithDisplayName("IDP"))

	idp.url = values.Bind2(idpURL, router.Addr(), func(urlStr string, addr string) string {
		u, _ := url.Parse(urlStr)
		host, _, _ := net.SplitHostPort(u.Host)
		_, port, err := net.SplitHostPort(addr)
		if err != nil {
			panic("bug: " + err.Error())
		}
		return u.ResolveReference(&url.URL{
			Host: fmt.Sprintf("%s:%s", host, port),
		}).String()
	})
	var err error
	idp.stateEncoder, err = jws.NewHS256Signer(env.SharedSecret())
	env.Require().NoError(err)

	idp.id = values.Bind2(idp.url, env.AuthenticateURL(), func(idpUrl, authUrl string) string {
		provider := identity.Provider{
			AuthenticateServiceUrl: authUrl,
			ClientId:               "CLIENT_ID",
			ClientSecret:           "CLIENT_SECRET",
			Type:                   "oidc",
			Scopes:                 []string{"openid", "email", "profile"},
			Url:                    idpUrl,
		}
		return provider.Hash()
	})

	router.Handle("/.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(&jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{idp.publicJWK},
		})
	})
	router.Handle("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		log.Ctx(ctx).Debug().Str("method", r.Method).Str("uri", r.RequestURI).Send()
		rootURL, _ := url.Parse(idp.url.Value())
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
			config["device_authorization_endpoint"] =
				rootURL.ResolveReference(&url.URL{Path: "/oidc/device/code"}).String()
		}
		serveJSON(w, config)
	})
	router.Handle("/oidc/auth", idp.HandleAuth)
	router.Handle("/oidc/token", idp.HandleToken)
	router.Handle("/oidc/userinfo", idp.HandleUserInfo)
	if idp.enableDeviceAuth {
		router.Handle("/oidc/device/code", idp.HandleDeviceCode)
	}

	env.AddUpstream(router)
}

// Modify implements testenv.Modifier.
func (idp *IDP) Modify(cfg *config.Config) {
	cfg.Options.Provider = "oidc"
	cfg.Options.ProviderURL = idp.url.Value()
	cfg.Options.ClientID = "CLIENT_ID"
	cfg.Options.ClientSecret = "CLIENT_SECRET"
	cfg.Options.Scopes = []string{"openid", "email", "profile"}
}

var _ testenv.Modifier = (*IDP)(nil)

func NewIDP(users []*User, opts ...IDPOption) *IDP {
	options := IDPOptions{
		enableTLS: true,
	}
	options.apply(opts...)

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
	for _, user := range users {
		user.ID = uuid.NewString()
		userLookup[user.ID] = user
	}
	return &IDP{
		IDPOptions: options,
		publicJWK:  publicJWK,
		signingKey: signingKey,
		userLookup: userLookup,
	}
}

// HandleAuth handles the auth flow for OIDC.
func (idp *IDP) HandleAuth(w http.ResponseWriter, r *http.Request) {
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
				"code": {State{
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

// HandleToken handles the token flow for OIDC.
func (idp *IDP) HandleToken(w http.ResponseWriter, r *http.Request) {
	if idp.enableDeviceAuth && r.FormValue("device_code") != "" {
		idp.serveToken(w, r, &State{
			ClientID: r.FormValue("client_id"),
			Email:    "fake.user@example.com",
		})
		return
	}

	rawCode := r.FormValue("code")
	state, err := DecodeState(rawCode)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	idp.serveToken(w, r, state)
}

func (idp *IDP) serveToken(w http.ResponseWriter, r *http.Request, state *State) {
	serveJSON(w, map[string]interface{}{
		"access_token":  state.Encode(),
		"refresh_token": state.Encode(),
		"token_type":    "Bearer",
		"id_token":      state.GetIDToken(r, idp.userLookup).Encode(idp.signingKey),
	})
}

// HandleUserInfo handles retrieving the user info.
func (idp *IDP) HandleUserInfo(w http.ResponseWriter, r *http.Request) {
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

	state, err := DecodeState(authz)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	serveJSON(w, state.GetUserInfo(idp.userLookup))
}

// HandleDeviceCode initiates a device auth code flow.
//
// This is the bare minimum to simulate the device auth code flow. There is no client_id
// verification or any actual login.
func (idp *IDP) HandleDeviceCode(w http.ResponseWriter, r *http.Request) {
	deviceCode := "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS"
	userCode := "ABCD-EFGH"

	rootURL, _ := url.Parse(idp.url.Value())
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

type RootURLKey struct{}

var rootURLKey RootURLKey

// WithRootURL sets the Root URL in a context.
func WithRootURL(ctx context.Context, rootURL *url.URL) context.Context {
	return context.WithValue(ctx, rootURLKey, rootURL)
}

func getRootURL(r *http.Request) *url.URL {
	if u, ok := r.Context().Value(rootURLKey).(*url.URL); ok {
		return u
	}

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

type State struct {
	Email    string `json:"email"`
	ClientID string `json:"client_id"`
}

func DecodeState(rawCode string) (*State, error) {
	var state State
	bs, _ := base64.URLEncoding.DecodeString(rawCode)
	err := json.Unmarshal(bs, &state)
	if err != nil {
		return nil, err
	}
	return &state, nil
}

func (state State) Encode() string {
	bs, _ := json.Marshal(state)
	return base64.URLEncoding.EncodeToString(bs)
}

func (state State) GetIDToken(r *http.Request, users map[string]*User) *IDToken {
	token := &IDToken{
		UserInfo: state.GetUserInfo(users),

		Issuer:   getRootURL(r).String(),
		Audience: state.ClientID,
		Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour * 24 * 365)),
		IssuedAt: jwt.NewNumericDate(time.Now()),
	}
	return token
}

func (state State) GetUserInfo(users map[string]*User) *UserInfo {
	userInfo := &UserInfo{
		Subject: state.Email,
		Email:   state.Email,
	}

	for _, u := range users {
		if u.Email == state.Email {
			userInfo.Subject = u.ID
			userInfo.Name = u.FirstName + " " + u.LastName
			userInfo.FamilyName = u.LastName
			userInfo.GivenName = u.FirstName
		}
	}

	return userInfo
}

type UserInfo struct {
	Subject    string `json:"sub"`
	Name       string `json:"name"`
	Email      string `json:"email"`
	FamilyName string `json:"family_name"`
	GivenName  string `json:"given_name"`
}

type IDToken struct {
	*UserInfo

	Issuer   string           `json:"iss"`
	Audience string           `json:"aud"`
	Expiry   *jwt.NumericDate `json:"exp"`
	IssuedAt *jwt.NumericDate `json:"iat"`
}

func (token *IDToken) Encode(signingKey jose.SigningKey) string {
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
	ID        string
	Email     string
	FirstName string
	LastName  string
}
