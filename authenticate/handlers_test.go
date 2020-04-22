package authenticate

import (
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/pomerium/pomerium/internal/cryptutil"
	"github.com/pomerium/pomerium/internal/encoding"
	"github.com/pomerium/pomerium/internal/encoding/jws"
	"github.com/pomerium/pomerium/internal/encoding/mock"
	"github.com/pomerium/pomerium/internal/frontend"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/identity"
	"github.com/pomerium/pomerium/internal/identity/oidc"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/sessions/cookie"
	mstore "github.com/pomerium/pomerium/internal/sessions/mock"

	"github.com/google/go-cmp/cmp"
	"github.com/pomerium/pomerium/internal/urlutil"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/oauth2"
	"gopkg.in/square/go-jose.v2/jwt"
)

func testAuthenticate() *Authenticate {
	var auth Authenticate
	auth.RedirectURL, _ = url.Parse("https://auth.example.com/oauth/callback")
	auth.sharedKey = cryptutil.NewBase64Key()
	auth.cookieSecret = cryptutil.NewKey()
	auth.cookieOptions = &cookie.Options{Name: "name"}
	auth.templates = template.Must(frontend.NewTemplates())
	return &auth
}

func TestAuthenticate_RobotsTxt(t *testing.T) {
	auth := testAuthenticate()
	req, err := http.NewRequest("GET", "/robots.txt", nil)
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(auth.RobotsTxt)
	handler.ServeHTTP(rr, req)
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}
	expected := fmt.Sprintf("User-agent: *\nDisallow: /")
	if rr.Body.String() != expected {
		t.Errorf("handler returned wrong body: got %v want %v", rr.Body.String(), expected)
	}
}

func TestAuthenticate_Handler(t *testing.T) {
	auth := testAuthenticate()

	h := auth.Handler()
	if h == nil {
		t.Error("handler cannot be nil")
	}
	req := httptest.NewRequest("GET", "/robots.txt", nil)
	req.Header.Set("Accept", "application/json")

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	expected := fmt.Sprintf("User-agent: *\nDisallow: /")

	body := rr.Body.String()
	if body != expected {
		t.Errorf("handler returned unexpected body: got %v want %v", body, expected)
	}

	// cors preflight
	req = httptest.NewRequest(http.MethodOptions, "/.pomerium/sign_in", nil)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Access-Control-Request-Method", "GET")
	req.Header.Set("Access-Control-Request-Headers", "X-Requested-With")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	expected = fmt.Sprintf("User-agent: *\nDisallow: /")
	code := rr.Code
	if code != http.StatusOK {
		t.Errorf("bad preflight code")
	}
	resp := rr.Result()
	body = resp.Header.Get("vary")
	if body == "" {
		t.Errorf("handler returned unexpected body: got %v want %v", body, expected)
	}

}

func TestAuthenticate_SignIn(t *testing.T) {
	t.Parallel()
	aead, err := chacha20poly1305.NewX(cryptutil.NewKey())
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string

		scheme string
		host   string
		qp     map[string]string

		session  sessions.SessionStore
		provider identity.MockProvider
		encoder  encoding.MarshalUnmarshaler
		wantCode int
	}{
		{"good", "https", "corp.example.example", map[string]string{urlutil.QueryRedirectURI: "https://dst.some.example/"}, &mstore.Store{Session: &sessions.State{Email: "user@pomerium.io", AccessToken: &oauth2.Token{Expiry: time.Now().Add(10 * time.Second)}}}, identity.MockProvider{}, &mock.Encoder{}, http.StatusFound},
		{"good alternate port", "https", "corp.example.example:8443", map[string]string{urlutil.QueryRedirectURI: "https://dst.some.example/"}, &mstore.Store{Session: &sessions.State{Email: "user@pomerium.io", AccessToken: &oauth2.Token{Expiry: time.Now().Add(10 * time.Second)}}}, identity.MockProvider{}, &mock.Encoder{}, http.StatusFound},
		{"session not valid", "https", "corp.example.example", map[string]string{urlutil.QueryRedirectURI: "https://dst.some.example/"}, &mstore.Store{Session: &sessions.State{Email: "user@pomerium.io", AccessToken: &oauth2.Token{Expiry: time.Now().Add(-10 * time.Second)}}}, identity.MockProvider{}, &mock.Encoder{}, http.StatusFound},
		{"bad redirect uri query", "", "corp.example.example", map[string]string{urlutil.QueryRedirectURI: "^^^"}, &mstore.Store{Session: &sessions.State{Email: "user@pomerium.io", AccessToken: &oauth2.Token{Expiry: time.Now().Add(10 * time.Second)}}}, identity.MockProvider{}, &mock.Encoder{}, http.StatusBadRequest},
		{"bad marshal", "https", "corp.example.example", map[string]string{urlutil.QueryRedirectURI: "https://dst.some.example/"}, &mstore.Store{Session: &sessions.State{Email: "user@pomerium.io", AccessToken: &oauth2.Token{Expiry: time.Now().Add(10 * time.Second)}}}, identity.MockProvider{}, &mock.Encoder{MarshalError: errors.New("error")}, http.StatusBadRequest},
		{"session error", "https", "corp.example.example", map[string]string{urlutil.QueryRedirectURI: "https://dst.some.example/"}, &mstore.Store{LoadError: errors.New("error")}, identity.MockProvider{}, &mock.Encoder{}, http.StatusBadRequest},
		{"good with different programmatic redirect", "https", "corp.example.example", map[string]string{urlutil.QueryRedirectURI: "https://dst.some.example/", urlutil.QueryCallbackURI: "https://some.example"}, &mstore.Store{Session: &sessions.State{Email: "user@pomerium.io", AccessToken: &oauth2.Token{Expiry: time.Now().Add(10 * time.Second)}}}, identity.MockProvider{}, &mock.Encoder{}, http.StatusFound},
		{"encrypted encoder error", "https", "corp.example.example", map[string]string{urlutil.QueryRedirectURI: "https://dst.some.example/", urlutil.QueryCallbackURI: "https://some.example"}, &mstore.Store{Session: &sessions.State{Email: "user@pomerium.io", AccessToken: &oauth2.Token{Expiry: time.Now().Add(10 * time.Second)}}}, identity.MockProvider{}, &mock.Encoder{MarshalError: errors.New("error")}, http.StatusBadRequest},
		{"good with callback uri set", "https", "corp.example.example", map[string]string{urlutil.QueryCallbackURI: "https://some.example/", urlutil.QueryRedirectURI: "https://dst.some.example/"}, &mstore.Store{Session: &sessions.State{Email: "user@pomerium.io", AccessToken: &oauth2.Token{Expiry: time.Now().Add(10 * time.Second)}}}, identity.MockProvider{}, &mock.Encoder{}, http.StatusFound},
		{"bad callback uri set", "https", "corp.example.example", map[string]string{urlutil.QueryCallbackURI: "^", urlutil.QueryRedirectURI: "https://dst.some.example/"}, &mstore.Store{Session: &sessions.State{Email: "user@pomerium.io", AccessToken: &oauth2.Token{Expiry: time.Now().Add(10 * time.Second)}}}, identity.MockProvider{}, &mock.Encoder{}, http.StatusBadRequest},
		{"good programmatic request", "https", "corp.example.example", map[string]string{urlutil.QueryIsProgrammatic: "true", urlutil.QueryRedirectURI: "https://dst.some.example/"}, &mstore.Store{Session: &sessions.State{Email: "user@pomerium.io", AccessToken: &oauth2.Token{Expiry: time.Now().Add(10 * time.Second)}}}, identity.MockProvider{}, &mock.Encoder{}, http.StatusFound},
		{"good additional audience", "https", "corp.example.example", map[string]string{urlutil.QueryForwardAuth: "x.y.z", urlutil.QueryRedirectURI: "https://dst.some.example/"}, &mstore.Store{Session: &sessions.State{Email: "user@pomerium.io", AccessToken: &oauth2.Token{Expiry: time.Now().Add(10 * time.Second)}}}, identity.MockProvider{}, &mock.Encoder{}, http.StatusFound},
		{"good user impersonate", "https", "corp.example.example", map[string]string{urlutil.QueryImpersonateAction: "set", urlutil.QueryRedirectURI: "https://dst.some.example/"}, &mstore.Store{Session: &sessions.State{Email: "user@pomerium.io", AccessToken: &oauth2.Token{Expiry: time.Now().Add(10 * time.Second)}}}, identity.MockProvider{}, &mock.Encoder{}, http.StatusFound},
		{"bad user impersonate save failure", "https", "corp.example.example", map[string]string{urlutil.QueryImpersonateAction: "set", urlutil.QueryRedirectURI: "https://dst.some.example/"}, &mstore.Store{SaveError: errors.New("err"), Session: &sessions.State{Email: "user@pomerium.io", AccessToken: &oauth2.Token{Expiry: time.Now().Add(10 * time.Second)}}}, identity.MockProvider{}, &mock.Encoder{}, http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Authenticate{
				sessionStore:     tt.session,
				provider:         tt.provider,
				RedirectURL:      uriParseHelper("https://some.example"),
				sharedKey:        "secret",
				sharedEncoder:    tt.encoder,
				encryptedEncoder: tt.encoder,
				sharedCipher:     aead,
				cookieOptions: &cookie.Options{
					Name:   "cookie",
					Domain: "foo",
				},
			}
			uri := &url.URL{Scheme: tt.scheme, Host: tt.host}

			queryString := uri.Query()
			for k, v := range tt.qp {
				queryString.Set(k, v)
			}
			uri.RawQuery = queryString.Encode()
			r := httptest.NewRequest(http.MethodGet, uri.String(), nil)
			r.Header.Set("Accept", "application/json")
			state, err := tt.session.LoadSession(r)
			ctx := r.Context()
			ctx = sessions.NewContext(ctx, state, err)
			r = r.WithContext(ctx)

			w := httptest.NewRecorder()
			httputil.HandlerFunc(a.SignIn).ServeHTTP(w, r)
			if status := w.Code; status != tt.wantCode {
				t.Errorf("handler returned wrong status code: got %v want %v %s", status, tt.wantCode, uri)
				t.Errorf("\n%+v", w.Body)
			}
		})
	}
}

func uriParseHelper(s string) *url.URL {
	uri, _ := url.Parse(s)
	return uri
}

func TestAuthenticate_SignOut(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		method string

		ctxError    error
		redirectURL string
		sig         string
		ts          string

		provider     identity.Authenticator
		sessionStore sessions.SessionStore
		wantCode     int
		wantBody     string
	}{
		{"good post", http.MethodPost, nil, "https://corp.pomerium.io/", "sig", "ts", identity.MockProvider{LogOutResponse: (*uriParseHelper("https://microsoft.com"))}, &mstore.Store{Encrypted: true, Session: &sessions.State{Email: "user@pomerium.io", AccessToken: &oauth2.Token{Expiry: time.Now().Add(10 * time.Second)}}}, http.StatusFound, ""},
		{"failed revoke", http.MethodPost, nil, "https://corp.pomerium.io/", "sig", "ts", identity.MockProvider{RevokeError: errors.New("OH NO")}, &mstore.Store{Encrypted: true, Session: &sessions.State{Email: "user@pomerium.io", AccessToken: &oauth2.Token{Expiry: time.Now().Add(10 * time.Second)}}}, http.StatusBadRequest, "{\"Status\":400,\"Error\":\"Bad Request: OH NO\"}\n"},
		{"load session error", http.MethodPost, errors.New("error"), "https://corp.pomerium.io/", "sig", "ts", identity.MockProvider{RevokeError: errors.New("OH NO")}, &mstore.Store{Encrypted: true, Session: &sessions.State{Email: "user@pomerium.io", AccessToken: &oauth2.Token{Expiry: time.Now().Add(10 * time.Second)}}}, http.StatusBadRequest, "{\"Status\":400,\"Error\":\"Bad Request: error\"}\n"},
		{"bad redirect uri", http.MethodPost, nil, "corp.pomerium.io/", "sig", "ts", identity.MockProvider{LogOutError: oidc.ErrSignoutNotImplemented}, &mstore.Store{Encrypted: true, Session: &sessions.State{Email: "user@pomerium.io", AccessToken: &oauth2.Token{Expiry: time.Now().Add(10 * time.Second)}}}, http.StatusBadRequest, "{\"Status\":400,\"Error\":\"Bad Request: corp.pomerium.io/ url does contain a valid scheme\"}\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			a := &Authenticate{
				sessionStore:     tt.sessionStore,
				provider:         tt.provider,
				encryptedEncoder: mock.Encoder{},
				templates:        template.Must(frontend.NewTemplates()),
			}
			u, _ := url.Parse("/sign_out")
			params, _ := url.ParseQuery(u.RawQuery)
			params.Add("sig", tt.sig)
			params.Add("ts", tt.ts)
			params.Add(urlutil.QueryRedirectURI, tt.redirectURL)
			u.RawQuery = params.Encode()
			r := httptest.NewRequest(tt.method, u.String(), nil)
			state, err := tt.sessionStore.LoadSession(r)
			if err != nil {
				t.Fatal(err)
			}
			ctx := r.Context()
			ctx = sessions.NewContext(ctx, state, tt.ctxError)
			r = r.WithContext(ctx)
			r.Header.Set("Accept", "application/json")

			w := httptest.NewRecorder()
			httputil.HandlerFunc(a.SignOut).ServeHTTP(w, r)
			if status := w.Code; status != tt.wantCode {
				t.Errorf("handler returned wrong status code: got %v want %v", status, tt.wantCode)
			}
			body := w.Body.String()
			if diff := cmp.Diff(body, tt.wantBody); diff != "" {
				t.Errorf("handler returned wrong body Body: %s", diff)
			}

		})
	}
}

func TestAuthenticate_OAuthCallback(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		method string

		ts            int64
		stateOvveride string
		extraMac      string
		extraState    string
		paramErr      string
		code          string
		redirectURI   string

		authenticateURL string
		session         sessions.SessionStore
		provider        identity.MockProvider

		want     string
		wantCode int
	}{
		{"good", http.MethodGet, time.Now().Unix(), "", "", "", "", "code", "https://corp.pomerium.io", "https://authenticate.pomerium.io", &mstore.Store{}, identity.MockProvider{AuthenticateResponse: sessions.State{Email: "user@pomerium.io", AccessToken: &oauth2.Token{Expiry: time.Now().Add(10 * time.Second)}}}, "https://corp.pomerium.io", http.StatusFound},
		{"failed authenticate", http.MethodGet, time.Now().Unix(), "", "", "", "", "code", "https://corp.pomerium.io", "https://authenticate.pomerium.io", &mstore.Store{}, identity.MockProvider{AuthenticateError: errors.New("error")}, "", http.StatusInternalServerError},
		{"failed save session", http.MethodGet, time.Now().Unix(), "", "", "", "", "code", "https://corp.pomerium.io", "https://authenticate.pomerium.io", &mstore.Store{SaveError: errors.New("error")}, identity.MockProvider{AuthenticateResponse: sessions.State{Email: "user@pomerium.io", AccessToken: &oauth2.Token{Expiry: time.Now().Add(10 * time.Second)}}}, "", http.StatusInternalServerError},
		{"provider returned error", http.MethodGet, time.Now().Unix(), "", "", "", "idp error", "code", "https://corp.pomerium.io", "https://authenticate.pomerium.io", &mstore.Store{}, identity.MockProvider{AuthenticateResponse: sessions.State{Email: "user@pomerium.io", AccessToken: &oauth2.Token{Expiry: time.Now().Add(10 * time.Second)}}}, "", http.StatusBadRequest},
		{"provider returned error imply 401", http.MethodGet, time.Now().Unix(), "", "", "", "access_denied", "code", "https://corp.pomerium.io", "https://authenticate.pomerium.io", &mstore.Store{}, identity.MockProvider{AuthenticateResponse: sessions.State{Email: "user@pomerium.io", AccessToken: &oauth2.Token{Expiry: time.Now().Add(10 * time.Second)}}}, "", http.StatusUnauthorized},
		{"empty code", http.MethodGet, time.Now().Unix(), "", "", "", "", "", "https://corp.pomerium.io", "https://authenticate.pomerium.io", &mstore.Store{}, identity.MockProvider{AuthenticateResponse: sessions.State{Email: "user@pomerium.io", AccessToken: &oauth2.Token{Expiry: time.Now().Add(10 * time.Second)}}}, "", http.StatusBadRequest},
		{"invalid redirect uri", http.MethodGet, time.Now().Unix(), "", "", "", "", "code", "corp.pomerium.io", "https://authenticate.pomerium.io", &mstore.Store{}, identity.MockProvider{AuthenticateResponse: sessions.State{Email: "user@pomerium.io", AccessToken: &oauth2.Token{Expiry: time.Now().Add(10 * time.Second)}}}, "", http.StatusBadRequest},
		{"bad redirect uri", http.MethodGet, time.Now().Unix(), "", "", "", "", "code", "http://^^^", "https://authenticate.pomerium.io", &mstore.Store{}, identity.MockProvider{AuthenticateResponse: sessions.State{Email: "user@pomerium.io", AccessToken: &oauth2.Token{Expiry: time.Now().Add(10 * time.Second)}}}, "https://corp.pomerium.io", http.StatusBadRequest},
		{"bad timing - too soon", http.MethodGet, time.Now().Add(1 * time.Hour).Unix(), "", "", "", "", "code", "https://corp.pomerium.io", "https://authenticate.pomerium.io", &mstore.Store{}, identity.MockProvider{AuthenticateResponse: sessions.State{Email: "user@pomerium.io", AccessToken: &oauth2.Token{Expiry: time.Now().Add(10 * time.Second)}}}, "https://corp.pomerium.io", http.StatusBadRequest},
		{"bad timing - expired", http.MethodGet, time.Now().Add(-1 * time.Hour).Unix(), "", "", "", "", "code", "https://corp.pomerium.io", "https://authenticate.pomerium.io", &mstore.Store{}, identity.MockProvider{AuthenticateResponse: sessions.State{Email: "user@pomerium.io", AccessToken: &oauth2.Token{Expiry: time.Now().Add(10 * time.Second)}}}, "https://corp.pomerium.io", http.StatusBadRequest},
		{"bad base64", http.MethodGet, time.Now().Unix(), "", "", "^", "", "code", "https://corp.pomerium.io", "https://authenticate.pomerium.io", &mstore.Store{}, identity.MockProvider{AuthenticateResponse: sessions.State{Email: "user@pomerium.io", AccessToken: &oauth2.Token{Expiry: time.Now().Add(10 * time.Second)}}}, "https://corp.pomerium.io", http.StatusBadRequest},
		{"too many seperators", http.MethodGet, time.Now().Unix(), "", "", "|ok|now|what", "", "code", "https://corp.pomerium.io", "https://authenticate.pomerium.io", &mstore.Store{}, identity.MockProvider{AuthenticateResponse: sessions.State{Email: "user@pomerium.io", AccessToken: &oauth2.Token{Expiry: time.Now().Add(10 * time.Second)}}}, "https://corp.pomerium.io", http.StatusBadRequest},
		{"bad hmac", http.MethodGet, time.Now().Unix(), "", "NOTMAC", "", "", "code", "https://corp.pomerium.io", "https://authenticate.pomerium.io", &mstore.Store{}, identity.MockProvider{AuthenticateResponse: sessions.State{Email: "user@pomerium.io", AccessToken: &oauth2.Token{Expiry: time.Now().Add(10 * time.Second)}}}, "https://corp.pomerium.io", http.StatusBadRequest},
		{"bad hmac", http.MethodGet, time.Now().Unix(), base64.URLEncoding.EncodeToString([]byte("malformed_state")), "", "", "", "code", "https://corp.pomerium.io", "https://authenticate.pomerium.io", &mstore.Store{}, identity.MockProvider{AuthenticateResponse: sessions.State{Email: "user@pomerium.io", AccessToken: &oauth2.Token{Expiry: time.Now().Add(10 * time.Second)}}}, "https://corp.pomerium.io", http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			aead, err := chacha20poly1305.NewX(cryptutil.NewKey())
			if err != nil {
				t.Fatal(err)
			}
			authURL, _ := url.Parse(tt.authenticateURL)
			a := &Authenticate{
				RedirectURL:  authURL,
				sessionStore: tt.session,
				provider:     tt.provider,
				cookieCipher: aead,
			}
			u, _ := url.Parse("/oauthGet")
			params, _ := url.ParseQuery(u.RawQuery)
			params.Add("error", tt.paramErr)
			params.Add("code", tt.code)
			nonce := cryptutil.NewBase64Key() // mock csrf

			// (nonce|timestamp|redirect_url|encrypt(redirect_url),mac(nonce,ts))
			b := []byte(fmt.Sprintf("%s|%d|%s", nonce, tt.ts, tt.extraMac))

			enc := cryptutil.Encrypt(a.cookieCipher, []byte(tt.redirectURI), b)
			b = append(b, enc...)
			encodedState := base64.URLEncoding.EncodeToString(b)
			if tt.extraState != "" {
				encodedState += tt.extraState
			}
			if tt.stateOvveride != "" {
				encodedState = tt.stateOvveride
			}
			params.Add("state", encodedState)

			u.RawQuery = params.Encode()

			r := httptest.NewRequest(tt.method, u.String(), nil)
			r.Header.Set("Accept", "application/json")
			w := httptest.NewRecorder()
			httputil.HandlerFunc(a.OAuthCallback).ServeHTTP(w, r)
			if w.Result().StatusCode != tt.wantCode {
				t.Errorf("Authenticate.OAuthCallback() error = %v, wantErr %v\n%v", w.Result().StatusCode, tt.wantCode, w.Body.String())
				return
			}
		})
	}
}

func TestAuthenticate_SessionValidatorMiddleware(t *testing.T) {
	t.Parallel()
	fn := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintln(w, "RVSI FILIVS CAISAR")
		w.WriteHeader(http.StatusOK)
	})

	tests := []struct {
		name    string
		headers map[string]string

		session  sessions.SessionStore
		ctxError error
		provider identity.Authenticator

		wantStatus int
	}{
		{"good", nil, &mstore.Store{Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}}, nil, identity.MockProvider{RefreshResponse: sessions.State{AccessToken: &oauth2.Token{Expiry: time.Now().Add(10 * time.Minute)}}}, http.StatusOK},
		{"invalid session", nil, &mstore.Store{Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}}, errors.New("hi"), identity.MockProvider{}, http.StatusFound},
		{"good refresh expired", nil, &mstore.Store{Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(-10 * time.Minute))}}, nil, identity.MockProvider{RefreshResponse: sessions.State{AccessToken: &oauth2.Token{Expiry: time.Now().Add(10 * time.Minute)}}}, http.StatusOK},
		{"expired,refresh error", nil, &mstore.Store{Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(-10 * time.Minute))}}, sessions.ErrExpired, identity.MockProvider{RefreshError: errors.New("error")}, http.StatusFound},
		{"expired,save error", nil, &mstore.Store{SaveError: errors.New("error"), Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(-10 * time.Minute))}}, sessions.ErrExpired, identity.MockProvider{RefreshResponse: sessions.State{AccessToken: &oauth2.Token{Expiry: time.Now().Add(10 * time.Minute)}}}, http.StatusFound},
		{"expired XHR,refresh error", map[string]string{"X-Requested-With": "XmlHttpRequest"}, &mstore.Store{Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(-10 * time.Minute))}}, sessions.ErrExpired, identity.MockProvider{RefreshError: errors.New("error")}, http.StatusUnauthorized},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			aead, err := chacha20poly1305.NewX(cryptutil.NewKey())
			if err != nil {
				t.Fatal(err)
			}
			signer, err := jws.NewHS256Signer(nil, "mock")
			if err != nil {
				t.Fatal(err)
			}
			a := Authenticate{
				sharedKey:        cryptutil.NewBase64Key(),
				cookieSecret:     cryptutil.NewKey(),
				RedirectURL:      uriParseHelper("https://authenticate.corp.beyondperimeter.com"),
				sessionStore:     tt.session,
				provider:         tt.provider,
				cookieCipher:     aead,
				encryptedEncoder: signer,
			}
			r := httptest.NewRequest("GET", "/", nil)
			state, err := tt.session.LoadSession(r)
			if err != nil {
				t.Fatal(err)
			}
			ctx := r.Context()
			ctx = sessions.NewContext(ctx, state, tt.ctxError)
			r = r.WithContext(ctx)

			r.Header.Set("Accept", "application/json")
			if len(tt.headers) != 0 {
				for k, v := range tt.headers {
					r.Header.Set(k, v)
				}
			}
			w := httptest.NewRecorder()

			got := a.VerifySession(fn)
			got.ServeHTTP(w, r)
			if status := w.Code; status != tt.wantStatus {
				t.Errorf("VerifySession() error = %v, wantErr %v\n%v", w.Result().StatusCode, tt.wantStatus, w.Body.String())
			}
		})
	}
}

func TestAuthenticate_RefreshAPI(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string

		session  sessions.SessionStore
		ctxError error

		provider      identity.Authenticator
		secretEncoder encoding.MarshalUnmarshaler
		sharedEncoder encoding.MarshalUnmarshaler

		wantStatus int
	}{
		{"good", &mstore.Store{Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}}, nil, identity.MockProvider{RefreshResponse: sessions.State{AccessToken: &oauth2.Token{Expiry: time.Now().Add(10 * time.Minute)}}}, mock.Encoder{MarshalResponse: []byte("ok")}, mock.Encoder{MarshalResponse: []byte("ok")}, http.StatusOK},
		{"refresh error", &mstore.Store{Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}}, nil, identity.MockProvider{RefreshError: errors.New("error")}, mock.Encoder{MarshalResponse: []byte("ok")}, mock.Encoder{MarshalResponse: []byte("ok")}, http.StatusInternalServerError},
		{"session is not refreshable error", &mstore.Store{Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}}, errors.New("session error"), identity.MockProvider{RefreshResponse: sessions.State{AccessToken: &oauth2.Token{Expiry: time.Now().Add(10 * time.Minute)}}}, mock.Encoder{MarshalResponse: []byte("ok")}, mock.Encoder{MarshalResponse: []byte("ok")}, http.StatusBadRequest},
		{"secret encoder failed", &mstore.Store{Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}}, nil, identity.MockProvider{RefreshResponse: sessions.State{AccessToken: &oauth2.Token{Expiry: time.Now().Add(10 * time.Minute)}}}, mock.Encoder{MarshalError: errors.New("error")}, mock.Encoder{MarshalResponse: []byte("ok")}, http.StatusInternalServerError},
		{"shared encoder failed", &mstore.Store{Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}}, nil, identity.MockProvider{RefreshResponse: sessions.State{AccessToken: &oauth2.Token{Expiry: time.Now().Add(10 * time.Minute)}}}, mock.Encoder{MarshalResponse: []byte("ok")}, mock.Encoder{MarshalError: errors.New("error")}, http.StatusInternalServerError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			aead, err := chacha20poly1305.NewX(cryptutil.NewKey())
			if err != nil {
				t.Fatal(err)
			}
			a := Authenticate{
				sharedKey:        cryptutil.NewBase64Key(),
				cookieSecret:     cryptutil.NewKey(),
				RedirectURL:      uriParseHelper("https://authenticate.corp.beyondperimeter.com"),
				encryptedEncoder: tt.secretEncoder,
				sharedEncoder:    tt.sharedEncoder,
				sessionStore:     tt.session,
				provider:         tt.provider,
				cookieCipher:     aead,
			}
			r := httptest.NewRequest("GET", "/", nil)
			state, _ := tt.session.LoadSession(r)
			ctx := r.Context()
			ctx = sessions.NewContext(ctx, state, tt.ctxError)
			r = r.WithContext(ctx)

			r.Header.Set("Accept", "application/json")

			w := httptest.NewRecorder()
			httputil.HandlerFunc(a.RefreshAPI).ServeHTTP(w, r)
			if status := w.Code; status != tt.wantStatus {
				t.Errorf("VerifySession() error = %v, wantErr %v\n%v", w.Result().StatusCode, tt.wantStatus, w.Body.String())

			}
		})
	}
}
func TestAuthenticate_Refresh(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string

		session  sessions.SessionStore
		ctxError error

		provider      identity.Authenticator
		secretEncoder encoding.MarshalUnmarshaler
		sharedEncoder encoding.MarshalUnmarshaler

		wantStatus int
	}{
		{"good", &mstore.Store{Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}}, nil, identity.MockProvider{RefreshResponse: sessions.State{AccessToken: &oauth2.Token{Expiry: time.Now().Add(10 * time.Minute)}}}, mock.Encoder{MarshalResponse: []byte("ok")}, mock.Encoder{MarshalResponse: []byte("ok")}, http.StatusOK},
		{"bad session", &mstore.Store{}, errors.New("err"), identity.MockProvider{RefreshResponse: sessions.State{AccessToken: &oauth2.Token{Expiry: time.Now().Add(10 * time.Minute)}}}, mock.Encoder{MarshalResponse: []byte("ok")}, mock.Encoder{MarshalResponse: []byte("ok")}, http.StatusBadRequest},
		{"encoder error", &mstore.Store{Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}}, nil, identity.MockProvider{RefreshResponse: sessions.State{AccessToken: &oauth2.Token{Expiry: time.Now().Add(10 * time.Minute)}}}, mock.Encoder{MarshalResponse: []byte("ok")}, mock.Encoder{MarshalError: errors.New("err")}, http.StatusInternalServerError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			aead, err := chacha20poly1305.NewX(cryptutil.NewKey())
			if err != nil {
				t.Fatal(err)
			}
			a := Authenticate{
				sharedKey:        cryptutil.NewBase64Key(),
				cookieSecret:     cryptutil.NewKey(),
				RedirectURL:      uriParseHelper("https://authenticate.corp.beyondperimeter.com"),
				encryptedEncoder: tt.secretEncoder,
				sharedEncoder:    tt.sharedEncoder,
				sessionStore:     tt.session,
				provider:         tt.provider,
				cookieCipher:     aead,
			}
			r := httptest.NewRequest("GET", "/", nil)
			state, _ := tt.session.LoadSession(r)
			ctx := r.Context()
			ctx = sessions.NewContext(ctx, state, tt.ctxError)
			r = r.WithContext(ctx)

			r.Header.Set("Accept", "application/json")

			w := httptest.NewRecorder()
			httputil.HandlerFunc(a.Refresh).ServeHTTP(w, r)
			if status := w.Code; status != tt.wantStatus {
				t.Errorf("VerifySession() error = %v, wantErr %v\n%v", w.Result().StatusCode, tt.wantStatus, w.Body.String())

			}
		})
	}
}
