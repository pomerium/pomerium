package scenarios

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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
	id         values.Value[string]
	url        values.Value[string]
	serverCert *testenv.Certificate
	publicJWK  jose.JSONWebKey
	signingKey jose.SigningKey

	stateEncoder encoding.MarshalUnmarshaler
	userLookup   map[string]*User
}

// Attach implements testenv.Modifier.
func (i *IDP) Attach(ctx context.Context) {
	env := testenv.EnvFromContext(ctx)

	router := upstreams.HTTP(nil)

	i.url = values.Bind2(env.SubdomainURL("mock-idp"), router.Port(), func(urlStr string, port int) string {
		u, _ := url.Parse(urlStr)
		host, _, _ := net.SplitHostPort(u.Host)
		return u.ResolveReference(&url.URL{
			Scheme: "http",
			Host:   fmt.Sprintf("%s:%d", host, port),
		}).String()
	})
	var err error
	i.stateEncoder, err = jws.NewHS256Signer(env.SharedSecret())
	env.Require().NoError(err)

	i.id = values.Bind2(i.url, env.AuthenticateURL(), func(idpUrl, authUrl string) string {
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

	router.Handle("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(&jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{i.publicJWK},
		})
	})
	router.Handle("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		log.Ctx(ctx).Debug().Str("method", r.Method).Str("uri", r.RequestURI).Send()
		rootUrl, _ := url.Parse(i.url.Value())
		json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer":                 rootUrl.String(),
			"authorization_endpoint": rootUrl.ResolveReference(&url.URL{Path: "/oidc/auth"}).String(),
			"token_endpoint":         rootUrl.ResolveReference(&url.URL{Path: "/oidc/token"}).String(),
			"jwks_uri":               rootUrl.ResolveReference(&url.URL{Path: "/.well-known/jwks.json"}).String(),
			"userinfo_endpoint":      rootUrl.ResolveReference(&url.URL{Path: "/oidc/userinfo"}).String(),
			"id_token_signing_alg_values_supported": []string{
				"ES256",
			},
		})
	})
	router.Handle("/oidc/auth", i.HandleAuth)
	router.Handle("/oidc/token", i.HandleToken)
	router.Handle("/oidc/userinfo", i.HandleUserInfo)

	env.AddUpstream(router)
}

// Modify implements testenv.Modifier.
func (i *IDP) Modify(cfg *config.Config) {
	cfg.Options.Provider = "oidc"
	cfg.Options.ProviderURL = i.url.Value()
	cfg.Options.ClientID = "CLIENT_ID"
	cfg.Options.ClientSecret = "CLIENT_SECRET"
	cfg.Options.Scopes = []string{"openid", "email", "profile"}
}

var _ testenv.Modifier = (*IDP)(nil)

func NewIDP(users []*User) *IDP {
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
	rawCode := r.FormValue("code")

	state, err := DecodeState(rawCode)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

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

var RootURLKey = struct{}{}

// WithRootURL sets the Root URL in a context.
func WithRootURL(ctx context.Context, rootURL *url.URL) context.Context {
	return context.WithValue(ctx, RootURLKey, rootURL)
}

func getRootURL(r *http.Request) *url.URL {
	if u, ok := r.Context().Value(RootURLKey).(*url.URL); ok {
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
