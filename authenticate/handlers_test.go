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
)

func testAuthenticate() *Authenticate {
	var auth Authenticate
	auth.RedirectURL, _ = url.Parse("https://auth.example.com/oauth/callback")
	auth.SharedKey = "IzY7MOZwzfOkmELXgozHDKTxoT3nOYhwkcmUVINsRww="
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

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	expected := fmt.Sprintf("User-agent: *\nDisallow: /")

	body := rr.Body.String()
	if body != expected {
		t.Errorf("handler returned unexpected body: got %v want %v", body, expected)
	}
}

func TestAuthenticate_SignIn(t *testing.T) {
	tests := []struct {
		name        string
		state       string
		redirectURI string
		session     sessions.SessionStore
		restStore   sessions.SessionStore
		provider    identity.MockProvider
		cipher      cryptutil.Cipher
		wantCode    int
	}{
		{"good", "state=example", "https://some.example", &sessions.MockSessionStore{Session: &sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", RefreshDeadline: time.Now().Add(10 * time.Second)}}, &sessions.MockSessionStore{Session: &sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", RefreshDeadline: time.Now().Add(10 * time.Second)}}, identity.MockProvider{ValidateResponse: true}, &cryptutil.MockCipher{}, http.StatusFound},
		{"session not valid", "state=example", "https://some.example", &sessions.MockSessionStore{Session: &sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", RefreshDeadline: time.Now().Add(10 * time.Second)}}, &sessions.MockSessionStore{Session: &sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", RefreshDeadline: time.Now().Add(10 * time.Second)}}, identity.MockProvider{ValidateResponse: false}, &cryptutil.MockCipher{}, http.StatusFound},
		{"session expired good refresh", "state=example", "https://some.example", &sessions.MockSessionStore{Session: &sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", RefreshDeadline: time.Now().Add(-10 * time.Second)}}, &sessions.MockSessionStore{Session: &sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", RefreshDeadline: time.Now().Add(-10 * time.Second)}}, identity.MockProvider{ValidateResponse: true, RefreshResponse: &sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", RefreshDeadline: time.Now().Add(-10 * time.Second)}}, &cryptutil.MockCipher{}, http.StatusFound},
		{"session expired bad refresh", "state=example", "https://some.example", &sessions.MockSessionStore{Session: &sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", RefreshDeadline: time.Now().Add(-10 * time.Second)}}, &sessions.MockSessionStore{Session: &sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", RefreshDeadline: time.Now().Add(-10 * time.Second)}}, identity.MockProvider{ValidateResponse: true, RefreshError: errors.New("error")}, &cryptutil.MockCipher{}, http.StatusBadRequest}, // mocking hmac is meh
		{"session expired bad refresh save", "state=example", "https://some.example", &sessions.MockSessionStore{SaveError: errors.New("ruh roh"), Session: &sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", RefreshDeadline: time.Now().Add(-10 * time.Second)}}, &sessions.MockSessionStore{Session: &sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", RefreshDeadline: time.Now().Add(-10 * time.Second)}}, identity.MockProvider{ValidateResponse: true, RefreshResponse: &sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", RefreshDeadline: time.Now().Add(-10 * time.Second)}}, &cryptutil.MockCipher{}, http.StatusBadRequest},

		// {"no cookie found trying to load", "state=example", "https://some.example", &sessions.MockSessionStore{LoadError: http.ErrNoCookie, Session: &sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", RefreshDeadline: time.Now().Add(10 * time.Second)}}, &sessions.MockSessionStore{Session: &sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", RefreshDeadline: time.Now().Add(10 * time.Second)}}, identity.MockProvider{ValidateResponse: true}, &cryptutil.MockCipher{}, http.StatusInternalServerError},
		{"unexpected error trying to load session", "state=example", "https://some.example", &sessions.MockSessionStore{LoadError: errors.New("error"), Session: &sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", RefreshDeadline: time.Now().Add(10 * time.Second)}}, &sessions.MockSessionStore{Session: &sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", RefreshDeadline: time.Now().Add(10 * time.Second)}}, identity.MockProvider{ValidateResponse: true}, &cryptutil.MockCipher{}, http.StatusBadRequest},
		{"malformed form", "state=example", "https://some.example", &sessions.MockSessionStore{Session: &sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", RefreshDeadline: time.Now().Add(10 * time.Second)}}, &sessions.MockSessionStore{Session: &sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", RefreshDeadline: time.Now().Add(10 * time.Second)}}, identity.MockProvider{ValidateResponse: true}, &cryptutil.MockCipher{}, http.StatusInternalServerError},
		{"empty state", "state=", "https://some.example", &sessions.MockSessionStore{Session: &sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", RefreshDeadline: time.Now().Add(10 * time.Second)}}, &sessions.MockSessionStore{Session: &sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", RefreshDeadline: time.Now().Add(10 * time.Second)}}, identity.MockProvider{ValidateResponse: true}, &cryptutil.MockCipher{}, http.StatusBadRequest},
		{"malformed redirect uri", "state=example", "https://accounts.google.^", &sessions.MockSessionStore{Session: &sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", RefreshDeadline: time.Now().Add(10 * time.Second)}}, &sessions.MockSessionStore{Session: &sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", RefreshDeadline: time.Now().Add(10 * time.Second)}}, identity.MockProvider{ValidateResponse: true}, &cryptutil.MockCipher{}, http.StatusBadRequest},
		// actually caught by go's handler, but we should keep the test.
		{"bad redirect uri query", "state=nonce", "%gh&%ij", &sessions.MockSessionStore{Session: &sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", RefreshDeadline: time.Now().Add(10 * time.Second)}}, &sessions.MockSessionStore{Session: &sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", RefreshDeadline: time.Now().Add(10 * time.Second)}}, identity.MockProvider{ValidateResponse: true}, &cryptutil.MockCipher{}, http.StatusInternalServerError},
		{"marshal session failure", "state=example", "https://some.example", &sessions.MockSessionStore{Session: &sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", RefreshDeadline: time.Now().Add(10 * time.Second)}}, &sessions.MockSessionStore{Session: &sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", RefreshDeadline: time.Now().Add(10 * time.Second)}}, identity.MockProvider{ValidateResponse: true}, &cryptutil.MockCipher{MarshalError: errors.New("error")}, http.StatusInternalServerError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Authenticate{
				sessionStore: tt.session,
				provider:     tt.provider,
				RedirectURL:  uriParse("https://some.example"),
				csrfStore:    &sessions.MockCSRFStore{},
				SharedKey:    "secret",
				cipher:       tt.cipher,
			}
			uri := &url.URL{Host: "corp.some.example", Scheme: "https", Path: "/"}
			if tt.name == "malformed form" {
				uri.RawQuery = "example=%zzzzz"
			} else {
				uri.RawQuery = fmt.Sprintf("%s&redirect_uri=%s", tt.state, tt.redirectURI)
			}
			r := httptest.NewRequest(http.MethodGet, uri.String(), nil)
			r.Header.Set("Accept", "application/json")
			w := httptest.NewRecorder()

			a.SignIn(w, r)
			if status := w.Code; status != tt.wantCode {
				t.Errorf("handler returned wrong status code: got %v want %v %s", status, tt.wantCode, uri)
				t.Errorf("\n%+v", w.Body)
			}
		})
	}
}

type mockCipher struct{}

func (a mockCipher) Encrypt(s []byte) ([]byte, error) {
	if string(s) == "error" {
		return []byte(""), errors.New("error encrypting")
	}
	return []byte("OK"), nil
}

func (a mockCipher) Decrypt(s []byte) ([]byte, error) {
	if string(s) == "error" {
		return []byte(""), errors.New("error encrypting")
	}
	return []byte("OK"), nil
}
func (a mockCipher) Marshal(s interface{}) (string, error) { return "ok", nil }
func (a mockCipher) Unmarshal(s string, i interface{}) error {
	if s == "unmarshal error" || s == "error" {
		return errors.New("error")
	}
	return nil
}

func Test_getAuthCodeRedirectURL(t *testing.T) {
	tests := []struct {
		name        string
		redirectURL *url.URL
		state       string
		authCode    string
		want        string
	}{
		{"https", uriParse("https://www.pomerium.io"), "state", "auth-code", "https://www.pomerium.io?code=auth-code&state=state"},
		{"http", uriParse("http://www.pomerium.io"), "state", "auth-code", "http://www.pomerium.io?code=auth-code&state=state"},
		{"no subdomain", uriParse("http://pomerium.io"), "state", "auth-code", "http://pomerium.io?code=auth-code&state=state"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getAuthCodeRedirectURL(tt.redirectURL, tt.state, tt.authCode); got != tt.want {
				t.Errorf("getAuthCodeRedirectURL() = %v, want %v", got, tt.want)
			}
		})
	}
}

func uriParse(s string) *url.URL {
	uri, _ := url.Parse(s)
	return uri
}

func TestAuthenticate_SignOut(t *testing.T) {

	tests := []struct {
		name   string
		method string

		redirectURL string
		sig         string
		ts          string

		provider     identity.Authenticator
		sessionStore sessions.SessionStore
		wantCode     int
		wantBody     string
	}{
		{"good post", http.MethodPost, "https://corp.pomerium.io/", "sig", "ts", identity.MockProvider{}, &sessions.MockSessionStore{Session: &sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", Email: "blah@blah.com", RefreshDeadline: time.Now().Add(10 * time.Second)}}, http.StatusFound, ""},
		{"failed revoke", http.MethodPost, "https://corp.pomerium.io/", "sig", "ts", identity.MockProvider{RevokeError: errors.New("OH NO")}, &sessions.MockSessionStore{Session: &sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", Email: "blah@blah.com", RefreshDeadline: time.Now().Add(10 * time.Second)}}, http.StatusBadRequest, "could not revoke"},
		{"malformed form", http.MethodPost, "https://corp.pomerium.io/", "sig", "ts", identity.MockProvider{}, &sessions.MockSessionStore{Session: &sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", Email: "blah@blah.com", RefreshDeadline: time.Now().Add(10 * time.Second)}}, http.StatusInternalServerError, ""},
		{"load session error", http.MethodPost, "https://corp.pomerium.io/", "sig", "ts", identity.MockProvider{}, &sessions.MockSessionStore{LoadError: errors.New("hi"), Session: &sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", Email: "blah@blah.com", RefreshDeadline: time.Now().Add(10 * time.Second)}}, http.StatusFound, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Authenticate{
				sessionStore: tt.sessionStore,
				provider:     tt.provider,
				cipher:       mockCipher{},
				templates:    templates.New(),
			}
			u, _ := url.Parse("/sign_out")
			params, _ := url.ParseQuery(u.RawQuery)
			params.Add("sig", tt.sig)
			params.Add("ts", tt.ts)
			params.Add("redirect_uri", tt.redirectURL)
			u.RawQuery = params.Encode()
			if tt.name == "malformed form" {
				u.RawQuery = "example=%zzzzz"
			}
			r := httptest.NewRequest(tt.method, u.String(), nil)
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

func redirectURLSignature(rawRedirect string, timestamp time.Time, secret string) string {
	data := []byte(fmt.Sprint(rawRedirect, timestamp.Unix()))
	h := cryptutil.Hash(secret, data)
	return base64.URLEncoding.EncodeToString(h)
}

func TestAuthenticate_OAuthStart(t *testing.T) {
	tests := []struct {
		name               string
		method             string
		redirectURLSetting string

		redirectURL string
		sig         string
		ts          string

		provider  identity.Authenticator
		csrfStore sessions.MockCSRFStore
		// sessionStore sessions.SessionStore
		wantCode int
	}{
		{"good", http.MethodGet, "https://corp.pomerium.io/", "https://corp.pomerium.io/", redirectURLSignature("https://corp.pomerium.io/", time.Now(), "secret"), fmt.Sprint(time.Now().Unix()), identity.MockProvider{}, sessions.MockCSRFStore{}, http.StatusFound},
		{"bad timestamp", http.MethodGet, "https://corp.pomerium.io/", "https://corp.pomerium.io/", redirectURLSignature("https://corp.pomerium.io/", time.Now(), "secret"), fmt.Sprint(time.Now().Add(10 * time.Hour).Unix()), identity.MockProvider{}, sessions.MockCSRFStore{}, http.StatusBadRequest},
		{"missing redirect", http.MethodGet, "https://corp.pomerium.io/", "", redirectURLSignature("https://corp.pomerium.io/", time.Now(), "secret"), fmt.Sprint(time.Now().Unix()), identity.MockProvider{}, sessions.MockCSRFStore{}, http.StatusBadRequest},
		{"malformed redirect", http.MethodGet, "https://corp.pomerium.io/", "https://pomerium.com%zzzzz", redirectURLSignature("https://corp.pomerium.io/", time.Now(), "secret"), fmt.Sprint(time.Now().Unix()), identity.MockProvider{}, sessions.MockCSRFStore{}, http.StatusBadRequest},
		{"different domains", http.MethodGet, "https://corp.notpomerium.io/", "https://corp.pomerium.io/", redirectURLSignature("https://corp.pomerium.io/", time.Now(), "secret"), fmt.Sprint(time.Now().Unix()), identity.MockProvider{}, sessions.MockCSRFStore{}, http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Authenticate{
				RedirectURL: uriParse(tt.redirectURLSetting),
				csrfStore:   tt.csrfStore,
				provider:    tt.provider,
				SharedKey:   "secret",
				cipher:      mockCipher{},
			}
			u, _ := url.Parse("/oauth_start")
			params, _ := url.ParseQuery(u.RawQuery)
			params.Add("sig", tt.sig)
			params.Add("ts", tt.ts)
			params.Add("redirect_uri", tt.redirectURL)

			u.RawQuery = params.Encode()

			r := httptest.NewRequest(tt.method, u.String(), nil)
			r.Header.Set("Accept", "application/json")

			w := httptest.NewRecorder()

			a.OAuthStart(w, r)
			if status := w.Code; status != tt.wantCode {
				t.Errorf("handler returned wrong status code: got %v want %v\n%v", status, tt.wantCode, w.Body.String())
			}
		})
	}
}

func TestAuthenticate_OAuthCallback(t *testing.T) {
	tests := []struct {
		name   string
		method string

		// url params
		paramErr        string
		code            string
		state           string
		authenticateURL string
		session         sessions.SessionStore
		provider        identity.MockProvider
		csrfStore       sessions.MockCSRFStore

		want     string
		wantCode int
	}{
		{"good", http.MethodGet, "", "code", base64.URLEncoding.EncodeToString([]byte("nonce:https://corp.pomerium.io")), "https://authenticate.pomerium.io", &sessions.MockSessionStore{}, identity.MockProvider{AuthenticateResponse: sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", Email: "blah@blah.com", RefreshDeadline: time.Now().Add(10 * time.Second)}}, sessions.MockCSRFStore{ResponseCSRF: "csrf", Cookie: &http.Cookie{Value: "nonce"}}, "https://corp.pomerium.io", http.StatusFound},
		{"get csrf error", http.MethodGet, "", "code", base64.URLEncoding.EncodeToString([]byte("nonce:https://corp.pomerium.io")), "https://authenticate.pomerium.io", &sessions.MockSessionStore{}, identity.MockProvider{AuthenticateResponse: sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", Email: "blah@blah.com", RefreshDeadline: time.Now().Add(10 * time.Second)}}, sessions.MockCSRFStore{ResponseCSRF: "csrf", GetError: errors.New("error"), Cookie: &http.Cookie{Value: "not nonce"}}, "", http.StatusInternalServerError},
		{"csrf nonce error", http.MethodGet, "", "code", base64.URLEncoding.EncodeToString([]byte("nonce:https://corp.pomerium.io")), "https://authenticate.pomerium.io", &sessions.MockSessionStore{}, identity.MockProvider{AuthenticateResponse: sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", Email: "blah@blah.com", RefreshDeadline: time.Now().Add(10 * time.Second)}}, sessions.MockCSRFStore{ResponseCSRF: "csrf", Cookie: &http.Cookie{Value: "not nonce"}}, "", http.StatusInternalServerError},
		{"failed authenticate", http.MethodGet, "", "code", base64.URLEncoding.EncodeToString([]byte("nonce:https://corp.pomerium.io")), "https://authenticate.pomerium.io", &sessions.MockSessionStore{}, identity.MockProvider{AuthenticateError: errors.New("error")}, sessions.MockCSRFStore{ResponseCSRF: "csrf", Cookie: &http.Cookie{Value: "nonce"}}, "", http.StatusInternalServerError},
		{"failed save session", http.MethodGet, "", "code", base64.URLEncoding.EncodeToString([]byte("nonce:https://corp.pomerium.io")), "https://authenticate.pomerium.io", &sessions.MockSessionStore{SaveError: errors.New("error")}, identity.MockProvider{AuthenticateResponse: sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", Email: "blah@blah.com", RefreshDeadline: time.Now().Add(10 * time.Second)}}, sessions.MockCSRFStore{ResponseCSRF: "csrf", Cookie: &http.Cookie{Value: "nonce"}}, "", http.StatusInternalServerError},
		{"provider returned error", http.MethodGet, "idp error", "code", base64.URLEncoding.EncodeToString([]byte("nonce:https://corp.pomerium.io")), "https://authenticate.pomerium.io", &sessions.MockSessionStore{}, identity.MockProvider{AuthenticateResponse: sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", Email: "blah@blah.com", RefreshDeadline: time.Now().Add(10 * time.Second)}}, sessions.MockCSRFStore{ResponseCSRF: "csrf", Cookie: &http.Cookie{Value: "nonce"}}, "", http.StatusBadRequest},
		{"empty code", http.MethodGet, "", "", base64.URLEncoding.EncodeToString([]byte("nonce:https://corp.pomerium.io")), "https://authenticate.pomerium.io", &sessions.MockSessionStore{}, identity.MockProvider{AuthenticateResponse: sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", Email: "blah@blah.com", RefreshDeadline: time.Now().Add(10 * time.Second)}}, sessions.MockCSRFStore{ResponseCSRF: "csrf", Cookie: &http.Cookie{Value: "nonce"}}, "", http.StatusBadRequest},
		{"invalid state string", http.MethodGet, "", "code", "nonce:https://corp.pomerium.io", "https://authenticate.pomerium.io", &sessions.MockSessionStore{}, identity.MockProvider{AuthenticateResponse: sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", Email: "blah@blah.com", RefreshDeadline: time.Now().Add(10 * time.Second)}}, sessions.MockCSRFStore{ResponseCSRF: "csrf", Cookie: &http.Cookie{Value: "nonce"}}, "", http.StatusInternalServerError},
		{"malformed state", http.MethodGet, "", "code", base64.URLEncoding.EncodeToString([]byte("nonce")), "https://authenticate.pomerium.io", &sessions.MockSessionStore{}, identity.MockProvider{AuthenticateResponse: sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", Email: "blah@blah.com", RefreshDeadline: time.Now().Add(10 * time.Second)}}, sessions.MockCSRFStore{ResponseCSRF: "csrf", Cookie: &http.Cookie{Value: "nonce"}}, "", http.StatusInternalServerError},
		{"invalid redirect uri", http.MethodGet, "", "code", base64.URLEncoding.EncodeToString([]byte("nonce:corp.pomerium.io")), "https://authenticate.pomerium.io", &sessions.MockSessionStore{}, identity.MockProvider{AuthenticateResponse: sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", Email: "blah@blah.com", RefreshDeadline: time.Now().Add(10 * time.Second)}}, sessions.MockCSRFStore{ResponseCSRF: "csrf", Cookie: &http.Cookie{Value: "nonce"}}, "", http.StatusBadRequest},
		{"malformed form", http.MethodGet, "", "code", base64.URLEncoding.EncodeToString([]byte("nonce:https://corp.pomerium.io")), "https://authenticate.pomerium.io", &sessions.MockSessionStore{}, identity.MockProvider{AuthenticateResponse: sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", Email: "blah@blah.com", RefreshDeadline: time.Now().Add(10 * time.Second)}}, sessions.MockCSRFStore{ResponseCSRF: "csrf", Cookie: &http.Cookie{Value: "nonce"}}, "", http.StatusBadRequest},
		{"bad redirect uri", http.MethodGet, "", "code", base64.URLEncoding.EncodeToString([]byte("nonce:http://^^^")), "https://authenticate.pomerium.io", &sessions.MockSessionStore{}, identity.MockProvider{AuthenticateResponse: sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", Email: "blah@blah.com", RefreshDeadline: time.Now().Add(10 * time.Second)}}, sessions.MockCSRFStore{ResponseCSRF: "csrf", Cookie: &http.Cookie{Value: "nonce"}}, "https://corp.pomerium.io", http.StatusBadRequest},
		{"different domains", http.MethodGet, "", "code", base64.URLEncoding.EncodeToString([]byte("nonce:http://some.example.notpomerium.io")), "https://authenticate.pomerium.io", &sessions.MockSessionStore{}, identity.MockProvider{AuthenticateResponse: sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", Email: "blah@blah.com", RefreshDeadline: time.Now().Add(10 * time.Second)}}, sessions.MockCSRFStore{ResponseCSRF: "csrf", Cookie: &http.Cookie{Value: "nonce"}}, "https://corp.pomerium.io", http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authURL, _ := url.Parse(tt.authenticateURL)
			a := &Authenticate{
				RedirectURL:  authURL,
				sessionStore: tt.session,
				csrfStore:    tt.csrfStore,
				provider:     tt.provider,
			}
			u, _ := url.Parse("/oauthGet")
			params, _ := url.ParseQuery(u.RawQuery)
			params.Add("error", tt.paramErr)
			params.Add("code", tt.code)
			params.Add("state", tt.state)

			u.RawQuery = params.Encode()

			if tt.name == "malformed form" {
				u.RawQuery = "example=%zzzzz"
			}
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
	tests := []struct {
		name      string
		method    string
		idToken   string
		restStore sessions.SessionStore
		cipher    cryptutil.Cipher
		provider  identity.MockProvider
		want      string
	}{
		{"good", http.MethodPost, "token", &sessions.MockSessionStore{}, &cryptutil.MockCipher{}, identity.MockProvider{IDTokenToSessionResponse: sessions.State{IDToken: "ok"}}, ""},
		{"could not exchange identity for session", http.MethodPost, "token", &sessions.MockSessionStore{}, &cryptutil.MockCipher{}, identity.MockProvider{IDTokenToSessionError: errors.New("error")}, ""},
		{"missing token", http.MethodPost, "", &sessions.MockSessionStore{}, &cryptutil.MockCipher{}, identity.MockProvider{IDTokenToSessionResponse: sessions.State{IDToken: "ok"}}, "missing id token"},
		{"malformed form", http.MethodPost, "token", &sessions.MockSessionStore{}, &cryptutil.MockCipher{}, identity.MockProvider{IDTokenToSessionResponse: sessions.State{IDToken: "ok"}}, ""},
		{"can't marshal token", http.MethodPost, "token", &sessions.MockSessionStore{}, &cryptutil.MockCipher{MarshalError: errors.New("can't marshal token")}, identity.MockProvider{IDTokenToSessionResponse: sessions.State{IDToken: "ok"}}, "can't marshal token"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Authenticate{
				cipher:       tt.cipher,
				provider:     tt.provider,
				sessionStore: tt.restStore,
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
