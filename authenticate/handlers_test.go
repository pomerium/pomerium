package authenticate

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/pomerium/pomerium/internal/cryptutil"
	"github.com/pomerium/pomerium/internal/identity"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/templates"
	"golang.org/x/crypto/chacha20poly1305"
)

func testAuthenticate() *Authenticate {
	var auth Authenticate
	auth.RedirectURL, _ = url.Parse("https://auth.example.com/oauth/callback")
	auth.SharedKey = "IzY7MOZwzfOkmELXgozHDKTxoT3nOYhwkcmUVINsRww="
	auth.cookieSecret = []byte(auth.SharedKey)
	auth.templates = templates.New()
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
}

func TestAuthenticate_SignIn(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		state       string
		redirectURI string
		session     sessions.SessionStore
		restStore   sessions.SessionStore
		provider    identity.MockProvider
		encoder     cryptutil.SecureEncoder
		wantCode    int
	}{
		{"good", "state=example", "https://some.example", &sessions.MockSessionStore{Session: &sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", RefreshDeadline: time.Now().Add(10 * time.Second)}}, &sessions.MockSessionStore{Session: &sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", RefreshDeadline: time.Now().Add(10 * time.Second)}}, identity.MockProvider{ValidateResponse: true}, &cryptutil.MockEncoder{}, http.StatusFound},
		{"session not valid", "state=example", "https://some.example", &sessions.MockSessionStore{Session: &sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", RefreshDeadline: time.Now().Add(10 * time.Second)}}, &sessions.MockSessionStore{Session: &sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", RefreshDeadline: time.Now().Add(10 * time.Second)}}, identity.MockProvider{ValidateResponse: false}, &cryptutil.MockEncoder{}, http.StatusFound},
		{"session expired good refresh", "state=example", "https://some.example", &sessions.MockSessionStore{Session: &sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", RefreshDeadline: time.Now().Add(-10 * time.Second)}}, &sessions.MockSessionStore{Session: &sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", RefreshDeadline: time.Now().Add(-10 * time.Second)}}, identity.MockProvider{ValidateResponse: true, RefreshResponse: &sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", RefreshDeadline: time.Now().Add(-10 * time.Second)}}, &cryptutil.MockEncoder{}, http.StatusFound},
		{"session expired bad refresh", "state=example", "https://some.example", &sessions.MockSessionStore{Session: &sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", RefreshDeadline: time.Now().Add(-10 * time.Second)}}, &sessions.MockSessionStore{Session: &sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", RefreshDeadline: time.Now().Add(-10 * time.Second)}}, identity.MockProvider{ValidateResponse: true, RefreshError: errors.New("error")}, &cryptutil.MockEncoder{}, http.StatusFound}, // mocking hmac is meh
		{"session expired bad refresh save", "state=example", "https://some.example", &sessions.MockSessionStore{SaveError: errors.New("ruh roh"), Session: &sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", RefreshDeadline: time.Now().Add(-10 * time.Second)}}, &sessions.MockSessionStore{Session: &sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", RefreshDeadline: time.Now().Add(-10 * time.Second)}}, identity.MockProvider{ValidateResponse: true, RefreshResponse: &sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", RefreshDeadline: time.Now().Add(-10 * time.Second)}}, &cryptutil.MockEncoder{}, http.StatusFound},

		// {"no cookie found trying to load", "state=example", "https://some.example", &sessions.MockSessionStore{LoadError: http.ErrNoCookie, Session: &sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", RefreshDeadline: time.Now().Add(10 * time.Second)}}, &sessions.MockSessionStore{Session: &sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", RefreshDeadline: time.Now().Add(10 * time.Second)}}, identity.MockProvider{ValidateResponse: true}, &cryptutil.MockEncoder{}, http.StatusInternalServerError},
		{"unexpected error trying to load session", "state=example", "https://some.example", &sessions.MockSessionStore{LoadError: errors.New("error"), Session: &sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", RefreshDeadline: time.Now().Add(10 * time.Second)}}, &sessions.MockSessionStore{Session: &sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", RefreshDeadline: time.Now().Add(10 * time.Second)}}, identity.MockProvider{ValidateResponse: true}, &cryptutil.MockEncoder{}, http.StatusFound},
		{"empty state", "state=", "https://some.example", &sessions.MockSessionStore{Session: &sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", RefreshDeadline: time.Now().Add(10 * time.Second)}}, &sessions.MockSessionStore{Session: &sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", RefreshDeadline: time.Now().Add(10 * time.Second)}}, identity.MockProvider{ValidateResponse: true}, &cryptutil.MockEncoder{}, http.StatusFound},
		{"malformed redirect uri", "state=example", "https://accounts.google.^", &sessions.MockSessionStore{Session: &sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", RefreshDeadline: time.Now().Add(10 * time.Second)}}, &sessions.MockSessionStore{Session: &sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", RefreshDeadline: time.Now().Add(10 * time.Second)}}, identity.MockProvider{ValidateResponse: true}, &cryptutil.MockEncoder{}, http.StatusBadRequest},
		// actually caught by go's handler, but we should keep the test.
		{"bad redirect uri query", "state=nonce", "%gh&%ij", &sessions.MockSessionStore{Session: &sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", RefreshDeadline: time.Now().Add(10 * time.Second)}}, &sessions.MockSessionStore{Session: &sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", RefreshDeadline: time.Now().Add(10 * time.Second)}}, identity.MockProvider{ValidateResponse: true}, &cryptutil.MockEncoder{}, http.StatusBadRequest},
		{"marshal session failure", "state=example", "https://some.example", &sessions.MockSessionStore{Session: &sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", RefreshDeadline: time.Now().Add(10 * time.Second)}}, &sessions.MockSessionStore{Session: &sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", RefreshDeadline: time.Now().Add(10 * time.Second)}}, identity.MockProvider{ValidateResponse: true}, &cryptutil.MockEncoder{MarshalError: errors.New("error")}, http.StatusFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Authenticate{
				sessionStore: tt.session,
				provider:     tt.provider,
				RedirectURL:  uriParseHelper("https://some.example"),
				SharedKey:    "secret",
				encoder:      tt.encoder,
			}
			uri := &url.URL{Host: "corp.some.example", Scheme: "https", Path: "/"}
			uri.RawQuery = fmt.Sprintf("%s&redirect_uri=%s", tt.state, tt.redirectURI)
			r := httptest.NewRequest(http.MethodGet, uri.String(), nil)
			r.Header.Set("Accept", "application/json")
			state, _ := tt.session.LoadSession(r)
			ctx := r.Context()
			ctx = sessions.NewContext(ctx, state, nil)
			r = r.WithContext(ctx)

			w := httptest.NewRecorder()

			a.SignIn(w, r)
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
		{"good post", http.MethodPost, nil, "https://corp.pomerium.io/", "sig", "ts", identity.MockProvider{}, &sessions.MockSessionStore{Session: &sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", Email: "blah@blah.com", RefreshDeadline: time.Now().Add(10 * time.Second)}}, http.StatusFound, ""},
		{"failed revoke", http.MethodPost, nil, "https://corp.pomerium.io/", "sig", "ts", identity.MockProvider{RevokeError: errors.New("OH NO")}, &sessions.MockSessionStore{Session: &sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", Email: "blah@blah.com", RefreshDeadline: time.Now().Add(10 * time.Second)}}, http.StatusBadRequest, "could not revoke"},
		{"load session error", http.MethodPost, errors.New("error"), "https://corp.pomerium.io/", "sig", "ts", identity.MockProvider{}, &sessions.MockSessionStore{LoadError: errors.New("hi"), Session: &sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", Email: "blah@blah.com", RefreshDeadline: time.Now().Add(10 * time.Second)}}, http.StatusBadRequest, ""},
		{"bad redirect uri", http.MethodPost, nil, "corp.pomerium.io/", "sig", "ts", identity.MockProvider{}, &sessions.MockSessionStore{Session: &sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", Email: "blah@blah.com", RefreshDeadline: time.Now().Add(10 * time.Second)}}, http.StatusBadRequest, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Authenticate{
				sessionStore: tt.sessionStore,
				provider:     tt.provider,
				templates:    templates.New(),
			}
			u, _ := url.Parse("/sign_out")
			params, _ := url.ParseQuery(u.RawQuery)
			params.Add("sig", tt.sig)
			params.Add("ts", tt.ts)
			params.Add("redirect_uri", tt.redirectURL)
			u.RawQuery = params.Encode()
			r := httptest.NewRequest(tt.method, u.String(), nil)
			state, _ := tt.sessionStore.LoadSession(r)
			ctx := r.Context()
			ctx = sessions.NewContext(ctx, state, tt.ctxError)
			r = r.WithContext(ctx)
			w := httptest.NewRecorder()

			a.SignOut(w, r)
			if status := w.Code; status != tt.wantCode {
				t.Errorf("handler returned wrong status code: got %v want %v", status, tt.wantCode)
			}
			if body := w.Body.String(); !strings.Contains(body, tt.wantBody) {
				t.Errorf("handler returned wrong body Body: got \n%s \n%s", body, tt.wantBody)
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
		{"good", http.MethodGet, time.Now().Unix(), "", "", "", "", "code", "https://corp.pomerium.io", "https://authenticate.pomerium.io", &sessions.MockSessionStore{}, identity.MockProvider{AuthenticateResponse: sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", Email: "blah@blah.com", RefreshDeadline: time.Now().Add(10 * time.Second)}}, "https://corp.pomerium.io", http.StatusFound},
		{"failed authenticate", http.MethodGet, time.Now().Unix(), "", "", "", "", "code", "https://corp.pomerium.io", "https://authenticate.pomerium.io", &sessions.MockSessionStore{}, identity.MockProvider{AuthenticateError: errors.New("error")}, "", http.StatusInternalServerError},
		{"failed save session", http.MethodGet, time.Now().Unix(), "", "", "", "", "code", "https://corp.pomerium.io", "https://authenticate.pomerium.io", &sessions.MockSessionStore{SaveError: errors.New("error")}, identity.MockProvider{AuthenticateResponse: sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", Email: "blah@blah.com", RefreshDeadline: time.Now().Add(10 * time.Second)}}, "", http.StatusInternalServerError},
		{"provider returned error", http.MethodGet, time.Now().Unix(), "", "", "", "idp error", "code", "https://corp.pomerium.io", "https://authenticate.pomerium.io", &sessions.MockSessionStore{}, identity.MockProvider{AuthenticateResponse: sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", Email: "blah@blah.com", RefreshDeadline: time.Now().Add(10 * time.Second)}}, "", http.StatusBadRequest},
		{"empty code", http.MethodGet, time.Now().Unix(), "", "", "", "", "", "https://corp.pomerium.io", "https://authenticate.pomerium.io", &sessions.MockSessionStore{}, identity.MockProvider{AuthenticateResponse: sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", Email: "blah@blah.com", RefreshDeadline: time.Now().Add(10 * time.Second)}}, "", http.StatusBadRequest},
		{"invalid redirect uri", http.MethodGet, time.Now().Unix(), "", "", "", "", "code", "corp.pomerium.io", "https://authenticate.pomerium.io", &sessions.MockSessionStore{}, identity.MockProvider{AuthenticateResponse: sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", Email: "blah@blah.com", RefreshDeadline: time.Now().Add(10 * time.Second)}}, "", http.StatusBadRequest},
		{"bad redirect uri", http.MethodGet, time.Now().Unix(), "", "", "", "", "code", "http://^^^", "https://authenticate.pomerium.io", &sessions.MockSessionStore{}, identity.MockProvider{AuthenticateResponse: sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", Email: "blah@blah.com", RefreshDeadline: time.Now().Add(10 * time.Second)}}, "https://corp.pomerium.io", http.StatusBadRequest},
		{"bad timing - too soon", http.MethodGet, time.Now().Add(1 * time.Hour).Unix(), "", "", "", "", "code", "https://corp.pomerium.io", "https://authenticate.pomerium.io", &sessions.MockSessionStore{}, identity.MockProvider{AuthenticateResponse: sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", Email: "blah@blah.com", RefreshDeadline: time.Now().Add(10 * time.Second)}}, "https://corp.pomerium.io", http.StatusBadRequest},
		{"bad timing - expired", http.MethodGet, time.Now().Add(-1 * time.Hour).Unix(), "", "", "", "", "code", "https://corp.pomerium.io", "https://authenticate.pomerium.io", &sessions.MockSessionStore{}, identity.MockProvider{AuthenticateResponse: sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", Email: "blah@blah.com", RefreshDeadline: time.Now().Add(10 * time.Second)}}, "https://corp.pomerium.io", http.StatusBadRequest},
		{"bad base64", http.MethodGet, time.Now().Unix(), "", "", "^", "", "code", "https://corp.pomerium.io", "https://authenticate.pomerium.io", &sessions.MockSessionStore{}, identity.MockProvider{AuthenticateResponse: sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", Email: "blah@blah.com", RefreshDeadline: time.Now().Add(10 * time.Second)}}, "https://corp.pomerium.io", http.StatusBadRequest},
		{"too many seperators", http.MethodGet, time.Now().Unix(), "", "", "|ok|now|what", "", "code", "https://corp.pomerium.io", "https://authenticate.pomerium.io", &sessions.MockSessionStore{}, identity.MockProvider{AuthenticateResponse: sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", Email: "blah@blah.com", RefreshDeadline: time.Now().Add(10 * time.Second)}}, "https://corp.pomerium.io", http.StatusBadRequest},
		{"bad hmac", http.MethodGet, time.Now().Unix(), "", "NOTMAC", "", "", "code", "https://corp.pomerium.io", "https://authenticate.pomerium.io", &sessions.MockSessionStore{}, identity.MockProvider{AuthenticateResponse: sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", Email: "blah@blah.com", RefreshDeadline: time.Now().Add(10 * time.Second)}}, "https://corp.pomerium.io", http.StatusBadRequest},
		{"bad hmac", http.MethodGet, time.Now().Unix(), base64.URLEncoding.EncodeToString([]byte("malformed_state")), "", "", "", "code", "https://corp.pomerium.io", "https://authenticate.pomerium.io", &sessions.MockSessionStore{}, identity.MockProvider{AuthenticateResponse: sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", Email: "blah@blah.com", RefreshDeadline: time.Now().Add(10 * time.Second)}}, "https://corp.pomerium.io", http.StatusBadRequest},
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
				cipher:       aead,
			}
			u, _ := url.Parse("/oauthGet")
			params, _ := url.ParseQuery(u.RawQuery)
			params.Add("error", tt.paramErr)
			params.Add("code", tt.code)
			nonce := cryptutil.NewBase64Key() // mock csrf

			// (nonce|timestamp|redirect_url|encrypt(redirect_url),mac(nonce,ts))
			b := []byte(fmt.Sprintf("%s|%d|%s", nonce, tt.ts, tt.extraMac))

			enc := cryptutil.Encrypt(a.cipher, []byte(tt.redirectURI), b)
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

			a.OAuthCallback(w, r)
			if w.Result().StatusCode != tt.wantCode {
				t.Errorf("Authenticate.OAuthCallback() error = %v, wantErr %v\n%v", w.Result().StatusCode, tt.wantCode, w.Body.String())
				return
			}
		})
	}
}

func TestAuthenticate_ExchangeToken(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		method    string
		idToken   string
		restStore sessions.SessionStore
		encoder   cryptutil.SecureEncoder
		provider  identity.MockProvider
		want      string
	}{
		{"good", http.MethodPost, "token", &sessions.MockSessionStore{}, &cryptutil.MockEncoder{}, identity.MockProvider{IDTokenToSessionResponse: sessions.State{IDToken: "ok"}}, ""},
		{"could not exchange identity for session", http.MethodPost, "token", &sessions.MockSessionStore{}, &cryptutil.MockEncoder{}, identity.MockProvider{IDTokenToSessionError: errors.New("error")}, ""},
		{"missing token", http.MethodPost, "", &sessions.MockSessionStore{}, &cryptutil.MockEncoder{}, identity.MockProvider{IDTokenToSessionResponse: sessions.State{IDToken: "ok"}}, "missing id token"},
		{"malformed form", http.MethodPost, "token", &sessions.MockSessionStore{}, &cryptutil.MockEncoder{}, identity.MockProvider{IDTokenToSessionResponse: sessions.State{IDToken: "ok"}}, ""},
		{"can't marshal token", http.MethodPost, "token", &sessions.MockSessionStore{}, &cryptutil.MockEncoder{MarshalError: errors.New("can't marshal token")}, identity.MockProvider{IDTokenToSessionResponse: sessions.State{IDToken: "ok"}}, "can't marshal token"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			aead, err := chacha20poly1305.NewX(cryptutil.NewKey())
			if err != nil {
				t.Fatal(err)
			}
			a := &Authenticate{
				encoder:      tt.encoder,
				provider:     tt.provider,
				sessionStore: tt.restStore,
				cipher:       aead,
			}
			form := url.Values{}
			if tt.idToken != "" {
				form.Add("id_token", tt.idToken)
			}
			rawForm := form.Encode()

			if tt.name == "malformed form" {
				rawForm = "example=%zzzzz"
			}
			r := httptest.NewRequest(tt.method, "/", strings.NewReader(rawForm))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.Header.Set("Accept", "application/json")

			w := httptest.NewRecorder()

			a.ExchangeToken(w, r)
			got := w.Body.String()
			if !strings.Contains(got, tt.want) {
				t.Errorf("Authenticate.ExchangeToken() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuthenticate_SessionValidatorMiddleware(t *testing.T) {
	t.Parallel()
	fn := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		fmt.Fprintln(w, "RVSI FILIVS CAISAR")
		w.WriteHeader(http.StatusOK)
	})

	tests := []struct {
		name     string
		session  sessions.SessionStore
		ctxError error
		provider identity.Authenticator

		wantStatus int
	}{
		{"good", &sessions.MockSessionStore{Session: &sessions.State{Email: "user@test.example", RefreshDeadline: time.Now().Add(10 * time.Second)}}, nil, identity.MockProvider{}, http.StatusOK},
		{"invalid session", &sessions.MockSessionStore{Session: &sessions.State{Email: "user@test.example", RefreshDeadline: time.Now().Add(10 * time.Second)}}, errors.New("hi"), identity.MockProvider{}, http.StatusFound},
		{"expired", &sessions.MockSessionStore{Session: &sessions.State{Email: "user@test.example", RefreshDeadline: time.Now().Add(-10 * time.Second)}}, sessions.ErrExpired, identity.MockProvider{}, http.StatusOK},
		{"expired,refresh error", &sessions.MockSessionStore{Session: &sessions.State{Email: "user@test.example", RefreshDeadline: time.Now().Add(-10 * time.Second)}}, sessions.ErrExpired, identity.MockProvider{RefreshError: errors.New("error")}, http.StatusFound},
		{"expired,save error", &sessions.MockSessionStore{SaveError: errors.New("error"), Session: &sessions.State{Email: "user@test.example", RefreshDeadline: time.Now().Add(-10 * time.Second)}}, sessions.ErrExpired, identity.MockProvider{}, http.StatusFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			aead, err := chacha20poly1305.NewX(cryptutil.NewKey())
			if err != nil {
				t.Fatal(err)
			}
			a := Authenticate{
				SharedKey:    "80ldlrU2d7w+wVpKNfevk6fmb8otEx6CqOfshj2LwhQ=",
				cookieSecret: []byte("80ldlrU2d7w+wVpKNfevk6fmb8otEx6CqOfshj2LwhQ="),
				RedirectURL:  uriParseHelper("https://authenticate.corp.beyondperimeter.com"),
				sessionStore: tt.session,
				provider:     tt.provider,
				cipher:       aead,
			}
			r := httptest.NewRequest("GET", "/", nil)
			state, _ := tt.session.LoadSession(r)
			ctx := r.Context()
			ctx = sessions.NewContext(ctx, state, tt.ctxError)
			r = r.WithContext(ctx)

			r.Header.Set("Accept", "application/json")

			w := httptest.NewRecorder()

			got := a.VerifySession(fn)
			got.ServeHTTP(w, r)
			if status := w.Code; status != tt.wantStatus {
				t.Errorf("VerifySession() error = %v, wantErr %v\n%v", w.Result().StatusCode, tt.wantStatus, w.Body.String())

			}
		})
	}
}
