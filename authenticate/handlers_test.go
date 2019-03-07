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
	auth.ProxyRootDomains = []string{"example.com"}
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

func TestAuthenticate_authenticate(t *testing.T) {
	// sessions.MockSessionStore{Session: expiredLifetime}
	goodSession := &sessions.MockSessionStore{
		Session: &sessions.SessionState{
			AccessToken:     "AccessToken",
			RefreshToken:    "RefreshToken",
			RefreshDeadline: time.Now().Add(10 * time.Second),
		}}

	expiredRefresPeriod := &sessions.MockSessionStore{
		Session: &sessions.SessionState{
			AccessToken:  "AccessToken",
			RefreshToken: "RefreshToken",

			RefreshDeadline: time.Now().Add(10 * -time.Second),
		}}

	tests := []struct {
		name     string
		session  sessions.SessionStore
		provider identity.MockProvider
		want     *sessions.SessionState
		wantErr  bool
	}{
		{"good", goodSession, identity.MockProvider{ValidateResponse: true}, nil, false},
		{"can't load session", &sessions.MockSessionStore{LoadError: errors.New("error")}, identity.MockProvider{ValidateResponse: true}, nil, true},
		{"validation fails", goodSession, identity.MockProvider{ValidateResponse: false}, nil, true},
		{"session fails after good validation", &sessions.MockSessionStore{SaveError: errors.New("error"), Session: &sessions.SessionState{AccessToken: "AccessToken", RefreshToken: "RefreshToken", RefreshDeadline: time.Now().Add(10 * time.Second)}}, identity.MockProvider{ValidateResponse: true}, nil, true},
		{"refresh expired", expiredRefresPeriod, identity.MockProvider{ValidateResponse: true, RefreshResponse: &sessions.SessionState{AccessToken: "new token", LifetimeDeadline: time.Now()}}, nil, false},
		{"refresh expired refresh error", expiredRefresPeriod, identity.MockProvider{ValidateResponse: true, RefreshError: errors.New("error")}, nil, true},
		{"refresh expired failed save", &sessions.MockSessionStore{SaveError: errors.New("error"), Session: &sessions.SessionState{AccessToken: "AccessToken", RefreshToken: "RefreshToken", RefreshDeadline: time.Now().Add(10 * -time.Second)}}, identity.MockProvider{ValidateResponse: true, RefreshResponse: &sessions.SessionState{AccessToken: "new token", LifetimeDeadline: time.Now()}}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Authenticate{
				sessionStore: tt.session,
				provider:     tt.provider,
			}
			r := httptest.NewRequest("GET", "/auth", nil)
			w := httptest.NewRecorder()

			_, err := p.authenticate(w, r)
			if (err != nil) != tt.wantErr {
				t.Errorf("Authenticate.authenticate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestAuthenticate_SignIn(t *testing.T) {
	tests := []struct {
		name     string
		session  sessions.SessionStore
		provider identity.MockProvider
		wantCode int
	}{
		{"good",
			&sessions.MockSessionStore{
				Session: &sessions.SessionState{
					AccessToken:     "AccessToken",
					RefreshToken:    "RefreshToken",
					RefreshDeadline: time.Now().Add(10 * time.Second),
				}},
			identity.MockProvider{ValidateResponse: true},

			http.StatusForbidden},
		{"session fails after good validation", &sessions.MockSessionStore{
			SaveError: errors.New("error"),
			Session: &sessions.SessionState{
				AccessToken:     "AccessToken",
				RefreshToken:    "RefreshToken",
				RefreshDeadline: time.Now().Add(10 * time.Second),
			}}, identity.MockProvider{ValidateResponse: true},
			http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Authenticate{
				sessionStore: tt.session,
				provider:     tt.provider,
				RedirectURL:  uriParse("http://www.pomerium.io"),
				csrfStore:    &sessions.MockCSRFStore{},
				SharedKey:    "secret",
				cipher:       mockCipher{},
			}
			r := httptest.NewRequest("GET", "/sign-in", nil)
			w := httptest.NewRecorder()

			a.SignIn(w, r)
			if status := w.Code; status != tt.wantCode {
				t.Errorf("handler returned wrong status code: got %v want %v", status, tt.wantCode)
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
	if string(s) == "unmarshal error" || string(s) == "error" {
		return errors.New("error")
	}
	return nil
}
func TestAuthenticate_ProxyCallback(t *testing.T) {

	tests := []struct {
		name string

		uri      string
		state    string
		authCode string

		sessionState *sessions.SessionState
		sessionStore sessions.SessionStore
		wantCode     int
		wantBody     string
	}{
		{"good", "https://corp.pomerium.io/", "state", "code",
			&sessions.SessionState{
				AccessToken:  "AccessToken",
				RefreshToken: "RefreshToken",

				RefreshDeadline: time.Now().Add(10 * time.Second),
			},
			&sessions.MockSessionStore{},
			302,
			"<a href=\"https://corp.pomerium.io/?code=ok&amp;state=state\">Found</a>."},
		{"no state",
			"https://corp.pomerium.io/",
			"",
			"code",
			&sessions.SessionState{
				AccessToken:  "AccessToken",
				RefreshToken: "RefreshToken",

				RefreshDeadline: time.Now().Add(10 * time.Second),
			},
			&sessions.MockSessionStore{},
			403,
			"no state parameter supplied"},
		{"no redirect_url",
			"",
			"state",
			"code",
			&sessions.SessionState{
				AccessToken:  "AccessToken",
				RefreshToken: "RefreshToken",

				RefreshDeadline: time.Now().Add(10 * time.Second),
			},
			&sessions.MockSessionStore{},
			403,
			"no redirect_uri parameter"},
		{"malformed redirect_url",
			"https://pomerium.com%zzzzz",
			"state",
			"code",
			&sessions.SessionState{
				AccessToken:  "AccessToken",
				RefreshToken: "RefreshToken",

				RefreshDeadline: time.Now().Add(10 * time.Second),
			},
			&sessions.MockSessionStore{},
			400,
			"malformed redirect_uri"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Authenticate{
				sessionStore: tt.sessionStore,
				cipher:       mockCipher{},
			}
			u, _ := url.Parse("https://pomerium.io/redirect")
			params, _ := url.ParseQuery(u.RawQuery)
			params.Set("code", tt.authCode)
			params.Set("state", tt.state)
			params.Set("redirect_uri", tt.uri)

			u.RawQuery = params.Encode()

			r := httptest.NewRequest("GET", u.String(), nil)
			w := httptest.NewRecorder()
			a.ProxyCallback(w, r, tt.sessionState)
			if status := w.Code; status != tt.wantCode {
				t.Errorf("handler returned wrong status code: got %v want %v", status, tt.wantCode)
			}
			if body := w.Body.String(); !strings.Contains(body, tt.wantBody) {
				t.Errorf("handler returned wrong body Body: got \n%s \n%s", body, tt.wantBody)
			}
		})
	}
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
		{"no scheme make https", uriParse("pomerium.io"), "state", "auth-code", "https://pomerium.io?code=auth-code&state=state"},
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
		{"good post",
			http.MethodPost,
			"https://corp.pomerium.io/",
			"sig",
			"ts",
			identity.MockProvider{},
			&sessions.MockSessionStore{
				Session: &sessions.SessionState{
					AccessToken:  "AccessToken",
					RefreshToken: "RefreshToken",
					Email:        "blah@blah.com",

					RefreshDeadline: time.Now().Add(10 * time.Second),
				},
			},
			http.StatusFound,
			""},
		{"failed revoke",
			http.MethodPost,
			"https://corp.pomerium.io/",
			"sig",
			"ts",
			identity.MockProvider{RevokeError: errors.New("OH NO")},
			&sessions.MockSessionStore{
				Session: &sessions.SessionState{
					AccessToken:  "AccessToken",
					RefreshToken: "RefreshToken",
					Email:        "blah@blah.com",

					RefreshDeadline: time.Now().Add(10 * time.Second),
				},
			},
			http.StatusBadRequest,
			"could not revoke"},

		{"good get",
			http.MethodGet,
			"https://corp.pomerium.io/",
			"sig",
			"ts",
			identity.MockProvider{},
			&sessions.MockSessionStore{
				Session: &sessions.SessionState{
					AccessToken:  "AccessToken",
					RefreshToken: "RefreshToken",
					Email:        "blah@blah.com",

					RefreshDeadline: time.Now().Add(10 * time.Second),
				},
			},
			http.StatusOK,
			"This will also sign you out of other internal apps."},
		{"cannot load session",
			http.MethodGet,
			"https://corp.pomerium.io/",
			"sig",
			"ts",
			identity.MockProvider{},
			&sessions.MockSessionStore{
				LoadError: errors.New("uh oh"),
				Session: &sessions.SessionState{
					AccessToken:  "AccessToken",
					RefreshToken: "RefreshToken",
					Email:        "blah@blah.com",

					RefreshDeadline: time.Now().Add(10 * time.Second),
				},
			},
			http.StatusBadRequest,
			"No session found to log out"},
		{"bad redirect url get",
			http.MethodGet,
			"https://pomerium.com%zzzzz",
			"sig",
			"ts",
			identity.MockProvider{},
			&sessions.MockSessionStore{
				Session: &sessions.SessionState{
					AccessToken:  "AccessToken",
					RefreshToken: "RefreshToken",
					Email:        "blah@blah.com",

					RefreshDeadline: time.Now().Add(10 * time.Second),
				},
			},
			http.StatusBadRequest,
			"Error"},
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
		name   string
		method string

		redirectURL    string
		sig            string
		ts             string
		allowedDomains []string

		provider  identity.Authenticator
		csrfStore sessions.MockCSRFStore
		// sessionStore sessions.SessionStore
		wantCode int
	}{
		{"good",
			http.MethodGet,
			"https://corp.pomerium.io/",
			redirectURLSignature("https://corp.pomerium.io/", time.Now(), "secret"),
			fmt.Sprint(time.Now().Unix()),
			[]string{".pomerium.io"},
			identity.MockProvider{},
			sessions.MockCSRFStore{},
			http.StatusFound,
		},
		{"bad timestamp",
			http.MethodGet,
			"https://corp.pomerium.io/",
			redirectURLSignature("https://corp.pomerium.io/", time.Now(), "secret"),
			fmt.Sprint(time.Now().Add(10 * time.Hour).Unix()),
			[]string{".pomerium.io"},
			identity.MockProvider{},
			sessions.MockCSRFStore{},
			http.StatusBadRequest,
		},
		{"domain not in allowed domains",
			http.MethodGet,
			"https://corp.pomerium.io/",
			redirectURLSignature("https://corp.pomerium.io/", time.Now(), "secret"),
			fmt.Sprint(time.Now().Unix()),
			[]string{"not.pomerium.io"},
			identity.MockProvider{},
			sessions.MockCSRFStore{},
			http.StatusBadRequest,
		},
		{"missing redirect",
			http.MethodGet,
			"",
			redirectURLSignature("https://corp.pomerium.io/", time.Now(), "secret"),
			fmt.Sprint(time.Now().Unix()),
			[]string{".pomerium.io"},
			identity.MockProvider{},
			sessions.MockCSRFStore{},
			http.StatusBadRequest,
		},
		{"malformed redirect",
			http.MethodGet,
			"https://pomerium.com%zzzzz",
			redirectURLSignature("https://corp.pomerium.io/", time.Now(), "secret"),
			fmt.Sprint(time.Now().Unix()),
			[]string{".pomerium.io"},
			identity.MockProvider{},
			sessions.MockCSRFStore{},
			http.StatusBadRequest,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Authenticate{
				ProxyRootDomains: tt.allowedDomains,
				RedirectURL:      uriParse("http://www.pomerium.io"),
				csrfStore:        tt.csrfStore,
				provider:         tt.provider,
				SharedKey:        "secret",
				cipher:           mockCipher{},
			}
			u, _ := url.Parse("/oauth_start")
			params, _ := url.ParseQuery(u.RawQuery)
			params.Add("sig", tt.sig)
			params.Add("ts", tt.ts)
			params.Add("redirect_uri", tt.redirectURL)

			u.RawQuery = params.Encode()

			r := httptest.NewRequest(tt.method, u.String(), nil)
			w := httptest.NewRecorder()

			a.OAuthStart(w, r)
			if status := w.Code; status != tt.wantCode {
				t.Errorf("handler returned wrong status code: got %v want %v", status, tt.wantCode)
			}
		})
	}
}

func TestAuthenticate_getOAuthCallback(t *testing.T) {

	tests := []struct {
		name   string
		method string

		// url params
		paramErr     string
		code         string
		state        string
		validDomains []string
		session      sessions.SessionStore
		provider     identity.MockProvider
		csrfStore    sessions.MockCSRFStore

		want    string
		wantErr bool
	}{
		{"good",
			http.MethodGet,
			"",
			"code",
			base64.URLEncoding.EncodeToString([]byte("nonce:https://corp.pomerium.io")),
			[]string{"pomerium.io"},

			&sessions.MockSessionStore{},
			identity.MockProvider{
				AuthenticateResponse: sessions.SessionState{
					AccessToken:  "AccessToken",
					RefreshToken: "RefreshToken",
					Email:        "blah@blah.com",

					RefreshDeadline: time.Now().Add(10 * time.Second),
				}},
			sessions.MockCSRFStore{
				ResponseCSRF: "csrf",
				Cookie:       &http.Cookie{Value: "nonce"}},
			"https://corp.pomerium.io",
			false,
		},
		{"get csrf error",
			http.MethodGet,
			"",
			"code",
			base64.URLEncoding.EncodeToString([]byte("nonce:https://corp.pomerium.io")),
			[]string{"pomerium.io"},

			&sessions.MockSessionStore{},
			identity.MockProvider{
				AuthenticateResponse: sessions.SessionState{
					AccessToken:  "AccessToken",
					RefreshToken: "RefreshToken",
					Email:        "blah@blah.com",

					RefreshDeadline: time.Now().Add(10 * time.Second),
				}},
			sessions.MockCSRFStore{
				ResponseCSRF: "csrf",
				GetError:     errors.New("error"),
				Cookie:       &http.Cookie{Value: "not nonce"}},
			"",
			true,
		},
		{"csrf nonce error",
			http.MethodGet,
			"",
			"code",
			base64.URLEncoding.EncodeToString([]byte("nonce:https://corp.pomerium.io")),
			[]string{"pomerium.io"},

			&sessions.MockSessionStore{},
			identity.MockProvider{
				AuthenticateResponse: sessions.SessionState{
					AccessToken:  "AccessToken",
					RefreshToken: "RefreshToken",
					Email:        "blah@blah.com",

					RefreshDeadline: time.Now().Add(10 * time.Second),
				}},
			sessions.MockCSRFStore{
				ResponseCSRF: "csrf",
				Cookie:       &http.Cookie{Value: "not nonce"}},
			"",
			true,
		},
		{"failed authenticate",
			http.MethodGet,
			"",
			"code",
			base64.URLEncoding.EncodeToString([]byte("nonce:https://corp.pomerium.io")),
			[]string{"pomerium.io"},

			&sessions.MockSessionStore{},
			identity.MockProvider{
				AuthenticateError: errors.New("error"),
			},
			sessions.MockCSRFStore{
				ResponseCSRF: "csrf",
				Cookie:       &http.Cookie{Value: "nonce"}},
			"",
			true,
		},
		{"failed save session",
			http.MethodGet,
			"",
			"code",
			base64.URLEncoding.EncodeToString([]byte("nonce:https://corp.pomerium.io")),
			[]string{"pomerium.io"},

			&sessions.MockSessionStore{SaveError: errors.New("error")},
			identity.MockProvider{
				AuthenticateResponse: sessions.SessionState{
					AccessToken:  "AccessToken",
					RefreshToken: "RefreshToken",
					Email:        "blah@blah.com",

					RefreshDeadline: time.Now().Add(10 * time.Second),
				}},
			sessions.MockCSRFStore{
				ResponseCSRF: "csrf",
				Cookie:       &http.Cookie{Value: "nonce"}},
			"",
			true,
		},

		{"error returned",
			http.MethodGet,
			"idp error",
			"code",
			base64.URLEncoding.EncodeToString([]byte("nonce:https://corp.pomerium.io")),
			[]string{"pomerium.io"},

			&sessions.MockSessionStore{},
			identity.MockProvider{
				AuthenticateResponse: sessions.SessionState{
					AccessToken:  "AccessToken",
					RefreshToken: "RefreshToken",
					Email:        "blah@blah.com",

					RefreshDeadline: time.Now().Add(10 * time.Second),
				}},
			sessions.MockCSRFStore{
				ResponseCSRF: "csrf",
				Cookie:       &http.Cookie{Value: "nonce"}},
			"",
			true,
		},
		{"empty code",
			http.MethodGet,
			"",
			"",
			base64.URLEncoding.EncodeToString([]byte("nonce:https://corp.pomerium.io")),
			[]string{"pomerium.io"},

			&sessions.MockSessionStore{},
			identity.MockProvider{
				AuthenticateResponse: sessions.SessionState{
					AccessToken:  "AccessToken",
					RefreshToken: "RefreshToken",
					Email:        "blah@blah.com",

					RefreshDeadline: time.Now().Add(10 * time.Second),
				}},
			sessions.MockCSRFStore{
				ResponseCSRF: "csrf",
				Cookie:       &http.Cookie{Value: "nonce"}},
			"",
			true,
		},
		{"invalid state string",
			http.MethodGet,
			"",
			"code",
			"nonce:https://corp.pomerium.io",
			[]string{"pomerium.io"},

			&sessions.MockSessionStore{},
			identity.MockProvider{
				AuthenticateResponse: sessions.SessionState{
					AccessToken:  "AccessToken",
					RefreshToken: "RefreshToken",
					Email:        "blah@blah.com",

					RefreshDeadline: time.Now().Add(10 * time.Second),
				}},
			sessions.MockCSRFStore{
				ResponseCSRF: "csrf",
				Cookie:       &http.Cookie{Value: "nonce"}},
			"",
			true,
		},
		{"malformed state",
			http.MethodGet,
			"",
			"code",
			base64.URLEncoding.EncodeToString([]byte("nonce")),
			[]string{"pomerium.io"},

			&sessions.MockSessionStore{},
			identity.MockProvider{
				AuthenticateResponse: sessions.SessionState{
					AccessToken:  "AccessToken",
					RefreshToken: "RefreshToken",
					Email:        "blah@blah.com",

					RefreshDeadline: time.Now().Add(10 * time.Second),
				}},
			sessions.MockCSRFStore{
				ResponseCSRF: "csrf",
				Cookie:       &http.Cookie{Value: "nonce"}},
			"",
			true,
		},
		{"invalid redirect uri",
			http.MethodGet,
			"",
			"code",
			base64.URLEncoding.EncodeToString([]byte("nonce:corp.pomerium.io")),
			[]string{"pomerium.io"},

			&sessions.MockSessionStore{},
			identity.MockProvider{
				AuthenticateResponse: sessions.SessionState{
					AccessToken:  "AccessToken",
					RefreshToken: "RefreshToken",
					Email:        "blah@blah.com",

					RefreshDeadline: time.Now().Add(10 * time.Second),
				}},
			sessions.MockCSRFStore{
				ResponseCSRF: "csrf",
				Cookie:       &http.Cookie{Value: "nonce"}},
			"",
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Authenticate{
				sessionStore:     tt.session,
				csrfStore:        tt.csrfStore,
				provider:         tt.provider,
				ProxyRootDomains: tt.validDomains,
			}
			u, _ := url.Parse("/oauthGet")
			params, _ := url.ParseQuery(u.RawQuery)
			params.Add("error", tt.paramErr)
			params.Add("code", tt.code)
			params.Add("state", tt.state)

			u.RawQuery = params.Encode()

			r := httptest.NewRequest(tt.method, u.String(), nil)
			w := httptest.NewRecorder()

			got, err := a.getOAuthCallback(w, r)
			if (err != nil) != tt.wantErr {
				t.Errorf("Authenticate.getOAuthCallback() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Authenticate.getOAuthCallback() = %v, want %v", got, tt.want)
			}
		})
	}
}
