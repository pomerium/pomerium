package proxy

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pomerium/pomerium/internal/config"
	"github.com/pomerium/pomerium/internal/cryptutil"
	"github.com/pomerium/pomerium/internal/policy"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/proxy/clients"
)

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
func (a mockCipher) Marshal(s interface{}) (string, error) {
	if s == "error" {
		return "", errors.New("error")
	}
	return "ok", nil
}
func (a mockCipher) Unmarshal(s string, i interface{}) error {
	if string(s) == "unmarshal error" || string(s) == "error" {
		return errors.New("error")
	}
	return nil
}

func TestProxy_RobotsTxt(t *testing.T) {
	proxy := Proxy{}
	req := httptest.NewRequest("GET", "/robots.txt", nil)
	rr := httptest.NewRecorder()
	proxy.RobotsTxt(rr, req)
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}
	expected := fmt.Sprintf("User-agent: *\nDisallow: /")
	if rr.Body.String() != expected {
		t.Errorf("handler returned wrong body: got %v want %v", rr.Body.String(), expected)
	}
}

func TestProxy_GetRedirectURL(t *testing.T) {

	tests := []struct {
		name string
		host string
		want *url.URL
	}{
		{"google", "google.com", &url.URL{Scheme: "https", Host: "google.com", Path: "/.pomerium/callback"}},
		{"pomerium", "pomerium.io", &url.URL{Scheme: "https", Host: "pomerium.io", Path: "/.pomerium/callback"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Proxy{redirectURL: &url.URL{Path: "/.pomerium/callback"}}

			if got := p.GetRedirectURL(tt.host); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Proxy.GetRedirectURL() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestProxy_signRedirectURL(t *testing.T) {
	tests := []struct {
		name        string
		rawRedirect string
		timestamp   time.Time
		want        string
	}{
		{"pomerium", "https://pomerium.io/.pomerium/callback", fixedDate, "wq3rAjRGN96RXS8TAzH-uxQTD0XgY_8ZYEKMiOLD5P4="},
		{"google", "https://google.com/.pomerium/callback", fixedDate, "7EYHZObq167CuyuPm5CqOtkU4zg5dFeUCs7W7QOrgNQ="},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Proxy{}
			if got := p.signRedirectURL(tt.rawRedirect, tt.timestamp); got != tt.want {
				t.Errorf("Proxy.signRedirectURL() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestProxy_GetSignOutURL(t *testing.T) {

	tests := []struct {
		name         string
		authenticate string
		redirect     string
		wantPrefix   string
	}{
		{"without scheme", "auth.corp.pomerium.io", "hello.corp.pomerium.io", "https://auth.corp.pomerium.io/sign_out?redirect_uri=https%3A%2F%2Fhello.corp.pomerium.io"},
		{"with scheme", "https://auth.corp.pomerium.io", "https://hello.corp.pomerium.io", "https://auth.corp.pomerium.io/sign_out?redirect_uri=https%3A%2F%2Fhello.corp.pomerium.io"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authenticateURL, _ := urlParse(tt.authenticate)
			redirectURL, _ := urlParse(tt.redirect)

			p := &Proxy{}
			// signature is ignored as it is tested above. Avoids testing time.Now
			if got := p.GetSignOutURL(authenticateURL, redirectURL); !strings.HasPrefix(got.String(), tt.wantPrefix) {
				t.Errorf("Proxy.GetSignOutURL() = %v, wantPrefix %v", got.String(), tt.wantPrefix)
			}
		})
	}
}

func TestProxy_GetSignInURL(t *testing.T) {

	tests := []struct {
		name         string
		authenticate string
		redirect     string
		state        string

		wantPrefix string
	}{
		{"without scheme", "auth.corp.pomerium.io", "hello.corp.pomerium.io", "example_state", "https://auth.corp.pomerium.io/sign_in?redirect_uri=https%3A%2F%2Fhello.corp.pomerium.io&response_type=code&shared_secret=shared-secret"},
		{"with scheme", "https://auth.corp.pomerium.io", "https://hello.corp.pomerium.io", "example_state", "https://auth.corp.pomerium.io/sign_in?redirect_uri=https%3A%2F%2Fhello.corp.pomerium.io&response_type=code&shared_secret=shared-secret"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Proxy{SharedKey: "shared-secret"}
			authenticateURL, _ := urlParse(tt.authenticate)
			redirectURL, _ := urlParse(tt.redirect)

			if got := p.GetSignInURL(authenticateURL, redirectURL, tt.state); !strings.HasPrefix(got.String(), tt.wantPrefix) {
				t.Errorf("Proxy.GetSignOutURL() = %v, wantPrefix %v", got.String(), tt.wantPrefix)
			}

		})
	}
}

func TestProxy_Signout(t *testing.T) {
	proxy, err := New(testOptions())
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "/.pomerium/sign_out", nil)
	rr := httptest.NewRecorder()
	proxy.SignOutCallback(rr, req)
	if status := rr.Code; status != http.StatusFound {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusFound)
	}
	// todo(bdd) : good way of mocking auth then serving a simple favicon?
}

func TestProxy_OAuthStart(t *testing.T) {
	proxy, err := New(testOptions())
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "/oauth-start", nil)

	rr := httptest.NewRecorder()
	proxy.OAuthStart(rr, req)
	// expect oauth redirect
	if status := rr.Code; status != http.StatusFound {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusFound)
	}
	// expected url
	expected := `<a href="https://authenticate.corp.beyondperimeter.com/sign_in`
	body := rr.Body.String()
	if !strings.HasPrefix(body, expected) {
		t.Errorf("handler returned unexpected body: got %v want %v", body, expected)
	}
}
func TestProxy_Handler(t *testing.T) {
	proxy, err := New(testOptions())
	if err != nil {
		t.Fatal(err)
	}
	h := proxy.Handler()
	if h == nil {
		t.Error("handler cannot be nil")
	}
	mux := http.NewServeMux()
	mux.Handle("/", h)
	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404 route not found for empty route")
	}
}

func Test_extendDeadline(t *testing.T) {
	tests := []struct {
		name string
		ttl  time.Duration
		want time.Time
	}{
		{"good", time.Second, time.Now().Add(time.Second).Truncate(time.Second)},
		{"test nanoseconds truncated", 500 * time.Nanosecond, time.Now().Truncate(time.Second)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extendDeadline(tt.ttl); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("extendDeadline() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestProxy_router(t *testing.T) {
	testPolicy := policy.Policy{From: "corp.example.com", To: "example.com"}
	testPolicy.Validate()
	policies := []policy.Policy{testPolicy}
	tests := []struct {
		name   string
		host   string
		mux    []policy.Policy
		route  http.Handler
		wantOk bool
	}{
		{"good corp", "https://corp.example.com", policies, nil, true},
		{"good with slash", "https://corp.example.com/", policies, nil, true},
		{"good with path", "https://corp.example.com/123", policies, nil, true},
		// {"multiple", "https://corp.example.com/", map[string]string{"corp.unrelated.com": "unrelated.com", "corp.example.com": "example.com"}, nil, true},
		{"bad corp", "https://notcorp.example.com/123", policies, nil, false},
		{"bad sub-sub", "https://notcorp.corp.example.com/123", policies, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := testOptions()
			opts.Policies = tt.mux
			p, err := New(opts)
			if err != nil {
				t.Fatal(err)
			}
			p.AuthenticateClient = clients.MockAuthenticate{}
			p.cipher = mockCipher{}

			req := httptest.NewRequest("GET", tt.host, nil)
			_, ok := p.router(req)
			if ok != tt.wantOk {
				t.Errorf("Proxy.router() ok = %v, want %v", ok, tt.wantOk)
			}
		})
	}
}

func TestProxy_Proxy(t *testing.T) {
	goodSession := &sessions.SessionState{
		AccessToken:     "AccessToken",
		RefreshToken:    "RefreshToken",
		RefreshDeadline: time.Now().Add(10 * time.Second),
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "RVSI FILIVS CAISAR")
	}))
	defer ts.Close()

	opts, optsWs := testOptionsTestServer(ts.URL), testOptionsTestServer(ts.URL)
	optsCORS := testOptionsWithCORS(ts.URL)
	optsPublic := testOptionsWithPublicAccess(ts.URL)
	optsWs.AllowWebsockets = true

	defaultHeaders, goodCORSHeaders, badCORSHeaders, headersWs := http.Header{}, http.Header{}, http.Header{}, http.Header{}
	goodCORSHeaders.Set("origin", "anything")
	goodCORSHeaders.Set("access-control-request-method", "anything")
	// missing "Origin"
	badCORSHeaders.Set("access-control-request-method", "anything")
	headersWs.Set("Connection", "Upgrade")
	headersWs.Set("Upgrade", "websocket")

	tests := []struct {
		name          string
		options       config.Options
		method        string
		header        http.Header
		host          string
		session       sessions.SessionStore
		authenticator clients.Authenticator
		authorizer    clients.Authorizer
		wantStatus    int
	}{
		{"good", opts, http.MethodGet, defaultHeaders, "https://httpbin.corp.example", &sessions.MockSessionStore{Session: goodSession}, clients.MockAuthenticate{ValidateResponse: true}, clients.MockAuthorize{AuthorizeResponse: true}, http.StatusOK},
		{"good cors preflight", optsCORS, http.MethodOptions, goodCORSHeaders, "https://httpbin.corp.example", &sessions.MockSessionStore{Session: goodSession}, clients.MockAuthenticate{ValidateResponse: true}, clients.MockAuthorize{AuthorizeResponse: false}, http.StatusOK},
		{"good email impersonation", opts, http.MethodGet, defaultHeaders, "https://httpbin.corp.example", &sessions.MockSessionStore{Session: &sessions.SessionState{AccessToken: "AccessToken", RefreshToken: "RefreshToken", RefreshDeadline: time.Now().Add(10 * time.Second), ImpersonateEmail: "test@user.example"}}, clients.MockAuthenticate{ValidateResponse: true}, clients.MockAuthorize{AuthorizeResponse: true}, http.StatusOK},
		{"good group impersonation", opts, http.MethodGet, defaultHeaders, "https://httpbin.corp.example", &sessions.MockSessionStore{Session: &sessions.SessionState{AccessToken: "AccessToken", RefreshToken: "RefreshToken", RefreshDeadline: time.Now().Add(10 * time.Second), ImpersonateGroups: []string{"group1", "group2"}}}, clients.MockAuthenticate{ValidateResponse: true}, clients.MockAuthorize{AuthorizeResponse: true}, http.StatusOK},
		// same request as above, but with cors_allow_preflight=false in the policy
		{"valid cors, but not allowed", opts, http.MethodOptions, goodCORSHeaders, "https://httpbin.corp.example", &sessions.MockSessionStore{Session: goodSession}, clients.MockAuthenticate{ValidateResponse: true}, clients.MockAuthorize{AuthorizeResponse: false}, http.StatusUnauthorized},
		// cors allowed, but the request is missing proper headers
		{"invalid cors headers", optsCORS, http.MethodOptions, badCORSHeaders, "https://httpbin.corp.example", &sessions.MockSessionStore{Session: goodSession}, clients.MockAuthenticate{ValidateResponse: true}, clients.MockAuthorize{AuthorizeResponse: false}, http.StatusUnauthorized},
		{"unexpected error", opts, http.MethodGet, defaultHeaders, "https://httpbin.corp.example", &sessions.MockSessionStore{LoadError: errors.New("ok")}, clients.MockAuthenticate{ValidateResponse: true}, clients.MockAuthorize{AuthorizeResponse: true}, http.StatusInternalServerError},
		// redirect to start auth process
		{"unknown host", opts, http.MethodGet, defaultHeaders, "https://nothttpbin.corp.example", &sessions.MockSessionStore{Session: goodSession}, clients.MockAuthenticate{ValidateResponse: true}, clients.MockAuthorize{AuthorizeResponse: true}, http.StatusNotFound},
		{"user not authorized", opts, http.MethodGet, defaultHeaders, "https://nothttpbin.corp.example", &sessions.MockSessionStore{Session: goodSession}, clients.MockAuthenticate{ValidateResponse: true}, clients.MockAuthorize{AuthorizeResponse: false}, http.StatusUnauthorized},
		{"authorization call failed", opts, http.MethodGet, defaultHeaders, "https://nothttpbin.corp.example", &sessions.MockSessionStore{Session: goodSession}, clients.MockAuthenticate{ValidateResponse: true}, clients.MockAuthorize{AuthorizeError: errors.New("error")}, http.StatusInternalServerError},
		// authenticate errors
		{"weird load session error", opts, http.MethodGet, defaultHeaders, "https://httpbin.corp.example", &sessions.MockSessionStore{LoadError: errors.New("weird"), Session: goodSession}, clients.MockAuthenticate{ValidateResponse: true}, clients.MockAuthorize{AuthorizeResponse: true}, http.StatusInternalServerError},
		{"failed refreshed session", opts, http.MethodGet, defaultHeaders, "https://httpbin.corp.example", &sessions.MockSessionStore{Session: &sessions.SessionState{RefreshDeadline: time.Now().Add(-10 * time.Second)}}, clients.MockAuthenticate{RefreshError: errors.New("refresh error")}, clients.MockAuthorize{AuthorizeResponse: true}, http.StatusForbidden},
		{"cannot resave refreshed session", opts, http.MethodGet, defaultHeaders, "https://httpbin.corp.example", &sessions.MockSessionStore{SaveError: errors.New("weird"), Session: &sessions.SessionState{RefreshDeadline: time.Now().Add(-10 * time.Second)}}, clients.MockAuthenticate{ValidateResponse: true}, clients.MockAuthorize{AuthorizeResponse: true}, http.StatusForbidden},
		{"authenticate validation error", opts, http.MethodGet, defaultHeaders, "https://httpbin.corp.example", &sessions.MockSessionStore{Session: goodSession}, clients.MockAuthenticate{ValidateResponse: false}, clients.MockAuthorize{AuthorizeResponse: true}, http.StatusForbidden},
		{"public access", optsPublic, http.MethodGet, defaultHeaders, "https://httpbin.corp.example", &sessions.MockSessionStore{Session: goodSession}, clients.MockAuthenticate{ValidateResponse: true}, clients.MockAuthorize{AuthorizeResponse: false}, http.StatusOK},
		{"public access, but unknown host", optsPublic, http.MethodGet, defaultHeaders, "https://nothttpbin.corp.example", &sessions.MockSessionStore{Session: goodSession}, clients.MockAuthenticate{ValidateResponse: true}, clients.MockAuthorize{AuthorizeResponse: false}, http.StatusUnauthorized},
		// no session, redirect to login
		{"no http found (no session)", opts, http.MethodGet, defaultHeaders, "https://httpbin.corp.example", &sessions.MockSessionStore{LoadError: http.ErrNoCookie}, clients.MockAuthenticate{ValidateResponse: true}, clients.MockAuthorize{AuthorizeResponse: true}, http.StatusBadRequest},
		// Should be expecting a 101 Switching Protocols, but expect a 200 OK because we don't have a websocket backend to respond
		{"ws supported, ws connection", optsWs, http.MethodGet, headersWs, "https://httpbin.corp.example", &sessions.MockSessionStore{Session: goodSession}, clients.MockAuthenticate{ValidateResponse: true}, clients.MockAuthorize{AuthorizeResponse: true}, http.StatusOK},
		{"ws supported, http connection", optsWs, http.MethodGet, defaultHeaders, "https://httpbin.corp.example", &sessions.MockSessionStore{Session: goodSession}, clients.MockAuthenticate{ValidateResponse: true}, clients.MockAuthorize{AuthorizeResponse: true}, http.StatusOK},
		{"ws unsupported, ws connection", opts, http.MethodGet, headersWs, "https://httpbin.corp.example", &sessions.MockSessionStore{Session: goodSession}, clients.MockAuthenticate{ValidateResponse: true}, clients.MockAuthorize{AuthorizeResponse: true}, http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := New(tt.options)
			if err != nil {
				t.Fatal(err)
			}
			p.cipher = mockCipher{}
			p.sessionStore = tt.session
			p.AuthenticateClient = tt.authenticator
			p.AuthorizeClient = tt.authorizer

			r := httptest.NewRequest(tt.method, tt.host, nil)
			r.Header = tt.header
			w := httptest.NewRecorder()
			p.Proxy(w, r)
			if status := w.Code; status != tt.wantStatus {
				t.Errorf("handler returned wrong status code: got %v want %v", status, tt.wantStatus)
				t.Errorf("\n%+v", w.Body.String())
				t.Errorf("\n%+v", opts)
				t.Errorf("\n%+v", ts.URL)

				t.Errorf("handler returned wrong status code: got %v want %v \n body %s", status, tt.wantStatus, w.Body.String())
			}

		})
	}
}

func TestProxy_UserDashboard(t *testing.T) {
	opts := testOptions()
	tests := []struct {
		name          string
		options       config.Options
		method        string
		cipher        cryptutil.Cipher
		session       sessions.SessionStore
		authenticator clients.Authenticator
		authorizer    clients.Authorizer

		wantAdminForm bool
		wantStatus    int
	}{
		{"good", opts, http.MethodGet, &cryptutil.MockCipher{}, &sessions.MockSessionStore{Session: &sessions.SessionState{Email: "user@test.example"}}, clients.MockAuthenticate{}, clients.MockAuthorize{}, false, http.StatusOK},
		{"cannot load session", opts, http.MethodGet, &cryptutil.MockCipher{}, &sessions.MockSessionStore{LoadError: errors.New("load error")}, clients.MockAuthenticate{}, clients.MockAuthorize{}, false, http.StatusBadRequest},
		{"auth failure, validation error", opts, http.MethodGet, &cryptutil.MockCipher{}, &sessions.MockSessionStore{Session: &sessions.SessionState{Email: "user@test.example", RefreshDeadline: time.Now().Add(10 * time.Second)}}, clients.MockAuthenticate{ValidateError: errors.New("not valid anymore"), ValidateResponse: false}, clients.MockAuthorize{}, false, http.StatusUnauthorized},
		{"can't save csrf", opts, http.MethodGet, &cryptutil.MockCipher{MarshalError: errors.New("err")}, &sessions.MockSessionStore{Session: &sessions.SessionState{Email: "user@test.example"}}, clients.MockAuthenticate{}, clients.MockAuthorize{}, false, http.StatusInternalServerError},
		{"want admin form good admin authorization", opts, http.MethodGet, &cryptutil.MockCipher{}, &sessions.MockSessionStore{Session: &sessions.SessionState{Email: "user@test.example"}}, clients.MockAuthenticate{}, clients.MockAuthorize{IsAdminResponse: true}, true, http.StatusOK},
		{"is admin but authorization fails", opts, http.MethodGet, &cryptutil.MockCipher{}, &sessions.MockSessionStore{Session: &sessions.SessionState{Email: "user@test.example"}}, clients.MockAuthenticate{}, clients.MockAuthorize{IsAdminError: errors.New("err")}, false, http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := New(tt.options)
			if err != nil {
				t.Fatal(err)
			}
			p.cipher = tt.cipher
			p.sessionStore = tt.session
			p.AuthenticateClient = tt.authenticator
			p.AuthorizeClient = tt.authorizer

			r := httptest.NewRequest(tt.method, "/", nil)
			w := httptest.NewRecorder()
			p.UserDashboard(w, r)
			if status := w.Code; status != tt.wantStatus {
				t.Errorf("status code: got %v want %v", status, tt.wantStatus)
				t.Errorf("\n%+v", opts)
			}
			if adminForm := strings.Contains(w.Body.String(), "impersonate"); adminForm != tt.wantAdminForm {
				t.Errorf("wanted admin form  got %v want %v", adminForm, tt.wantAdminForm)
				t.Errorf("\n%+v", w.Body.String())
			}
		})
	}
}

func TestProxy_Refresh(t *testing.T) {
	opts := testOptions()
	opts.RefreshCooldown = 0
	timeSinceError := testOptions()
	timeSinceError.RefreshCooldown = time.Duration(int(^uint(0) >> 1))

	tests := []struct {
		name          string
		options       config.Options
		method        string
		cipher        cryptutil.Cipher
		session       sessions.SessionStore
		authenticator clients.Authenticator
		authorizer    clients.Authorizer
		wantStatus    int
	}{
		{"good", opts, http.MethodGet, &cryptutil.MockCipher{}, &sessions.MockSessionStore{Session: &sessions.SessionState{Email: "user@test.example", IDToken: "eyJhbGciOiJSUzI1NiIsImtpZCI6IjA3YTA4MjgzOWYyZTcxYTliZjZjNTk2OTk2Yjk0NzM5Nzg1YWZkYzMiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiI4NTE4NzcwODIwNTktYmZna3BqMDlub29nN2FzM2dwYzN0N3I2bjlzamJnczYuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI4NTE4NzcwODIwNTktYmZna3BqMDlub29nN2FzM2dwYzN0N3I2bjlzamJnczYuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMTE0MzI2NTU5NzcyNzMxNTAzMDgiLCJoZCI6InBvbWVyaXVtLmlvIiwiZW1haWwiOiJiZGRAcG9tZXJpdW0uaW8iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiYXRfaGFzaCI6IlppQ1g0WndDYl9tcUVxM2xnbmFZRHciLCJuYW1lIjoiQm9iYnkgRGVTaW1vbmUiLCJwaWN0dXJlIjoiaHR0cHM6Ly9saDMuZ29vZ2xldXNlcmNvbnRlbnQuY29tLy1PX1BzRTlILTgzRS9BQUFBQUFBQUFBSS9BQUFBQUFBQUFBQS9BQ0hpM3JjQ0U0SFRLVDBhQk1pUFVfOEZfVXFOQ3F6RTBRL3M5Ni1jL3Bob3RvLmpwZyIsImdpdmVuX25hbWUiOiJCb2JieSIsImZhbWlseV9uYW1lIjoiRGVTaW1vbmUiLCJsb2NhbGUiOiJlbiIsImlhdCI6MTU1ODY1NDEzNywiZXhwIjoxNTU4NjU3NzM3fQ.Flah31XfqmPhWYh2rJ-6rtowmSQFgp6HqDf1rpS38Wo0DXnIYmXxEQVLanDNV62Z0sLhUk1QO9NqoSgA3NscM-Ww-JsqU80oKnWcMYweUb_KU0kfHyTiUB0iEHMqu6tXn5dA_dIaPnL5oorXZ_gG4sooRxBZrDkaNAjRINLciKDQkUTVaNfnM6IBZ_pWDPd2lWGtj8h8sEIe2PIiH73Z2VLlXz8kw60VTPsi9U2zrF0ZJ9MfRGJhceQ58vW2ZlFfXJixgvbOZjKmcRv8NaJDIUss48l0Bsya6icZ0l1ZK-sAiFr0KVLTl2ywu8d5SQpTJ1X7vDW_u_04xaqDQUdYKA"}}, clients.MockAuthenticate{}, clients.MockAuthorize{}, http.StatusFound},
		{"cannot load session", opts, http.MethodGet, &cryptutil.MockCipher{}, &sessions.MockSessionStore{LoadError: errors.New("load error")}, clients.MockAuthenticate{}, clients.MockAuthorize{}, http.StatusBadRequest},
		{"bad id token", opts, http.MethodGet, &cryptutil.MockCipher{}, &sessions.MockSessionStore{Session: &sessions.SessionState{Email: "user@test.example", IDToken: "bad"}}, clients.MockAuthenticate{}, clients.MockAuthorize{}, http.StatusInternalServerError},
		{"issue date too soon", timeSinceError, http.MethodGet, &cryptutil.MockCipher{}, &sessions.MockSessionStore{Session: &sessions.SessionState{Email: "user@test.example", IDToken: "eyJhbGciOiJSUzI1NiIsImtpZCI6IjA3YTA4MjgzOWYyZTcxYTliZjZjNTk2OTk2Yjk0NzM5Nzg1YWZkYzMiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiI4NTE4NzcwODIwNTktYmZna3BqMDlub29nN2FzM2dwYzN0N3I2bjlzamJnczYuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI4NTE4NzcwODIwNTktYmZna3BqMDlub29nN2FzM2dwYzN0N3I2bjlzamJnczYuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMTE0MzI2NTU5NzcyNzMxNTAzMDgiLCJoZCI6InBvbWVyaXVtLmlvIiwiZW1haWwiOiJiZGRAcG9tZXJpdW0uaW8iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiYXRfaGFzaCI6IlppQ1g0WndDYl9tcUVxM2xnbmFZRHciLCJuYW1lIjoiQm9iYnkgRGVTaW1vbmUiLCJwaWN0dXJlIjoiaHR0cHM6Ly9saDMuZ29vZ2xldXNlcmNvbnRlbnQuY29tLy1PX1BzRTlILTgzRS9BQUFBQUFBQUFBSS9BQUFBQUFBQUFBQS9BQ0hpM3JjQ0U0SFRLVDBhQk1pUFVfOEZfVXFOQ3F6RTBRL3M5Ni1jL3Bob3RvLmpwZyIsImdpdmVuX25hbWUiOiJCb2JieSIsImZhbWlseV9uYW1lIjoiRGVTaW1vbmUiLCJsb2NhbGUiOiJlbiIsImlhdCI6MTU1ODY1NDEzNywiZXhwIjoxNTU4NjU3NzM3fQ.Flah31XfqmPhWYh2rJ-6rtowmSQFgp6HqDf1rpS38Wo0DXnIYmXxEQVLanDNV62Z0sLhUk1QO9NqoSgA3NscM-Ww-JsqU80oKnWcMYweUb_KU0kfHyTiUB0iEHMqu6tXn5dA_dIaPnL5oorXZ_gG4sooRxBZrDkaNAjRINLciKDQkUTVaNfnM6IBZ_pWDPd2lWGtj8h8sEIe2PIiH73Z2VLlXz8kw60VTPsi9U2zrF0ZJ9MfRGJhceQ58vW2ZlFfXJixgvbOZjKmcRv8NaJDIUss48l0Bsya6icZ0l1ZK-sAiFr0KVLTl2ywu8d5SQpTJ1X7vDW_u_04xaqDQUdYKA"}}, clients.MockAuthenticate{}, clients.MockAuthorize{}, http.StatusBadRequest},
		{"refresh failure", opts, http.MethodGet, &cryptutil.MockCipher{}, &sessions.MockSessionStore{Session: &sessions.SessionState{Email: "user@test.example", IDToken: "eyJhbGciOiJSUzI1NiIsImtpZCI6IjA3YTA4MjgzOWYyZTcxYTliZjZjNTk2OTk2Yjk0NzM5Nzg1YWZkYzMiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiI4NTE4NzcwODIwNTktYmZna3BqMDlub29nN2FzM2dwYzN0N3I2bjlzamJnczYuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI4NTE4NzcwODIwNTktYmZna3BqMDlub29nN2FzM2dwYzN0N3I2bjlzamJnczYuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMTE0MzI2NTU5NzcyNzMxNTAzMDgiLCJoZCI6InBvbWVyaXVtLmlvIiwiZW1haWwiOiJiZGRAcG9tZXJpdW0uaW8iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiYXRfaGFzaCI6IlppQ1g0WndDYl9tcUVxM2xnbmFZRHciLCJuYW1lIjoiQm9iYnkgRGVTaW1vbmUiLCJwaWN0dXJlIjoiaHR0cHM6Ly9saDMuZ29vZ2xldXNlcmNvbnRlbnQuY29tLy1PX1BzRTlILTgzRS9BQUFBQUFBQUFBSS9BQUFBQUFBQUFBQS9BQ0hpM3JjQ0U0SFRLVDBhQk1pUFVfOEZfVXFOQ3F6RTBRL3M5Ni1jL3Bob3RvLmpwZyIsImdpdmVuX25hbWUiOiJCb2JieSIsImZhbWlseV9uYW1lIjoiRGVTaW1vbmUiLCJsb2NhbGUiOiJlbiIsImlhdCI6MTU1ODY1NDEzNywiZXhwIjoxNTU4NjU3NzM3fQ.Flah31XfqmPhWYh2rJ-6rtowmSQFgp6HqDf1rpS38Wo0DXnIYmXxEQVLanDNV62Z0sLhUk1QO9NqoSgA3NscM-Ww-JsqU80oKnWcMYweUb_KU0kfHyTiUB0iEHMqu6tXn5dA_dIaPnL5oorXZ_gG4sooRxBZrDkaNAjRINLciKDQkUTVaNfnM6IBZ_pWDPd2lWGtj8h8sEIe2PIiH73Z2VLlXz8kw60VTPsi9U2zrF0ZJ9MfRGJhceQ58vW2ZlFfXJixgvbOZjKmcRv8NaJDIUss48l0Bsya6icZ0l1ZK-sAiFr0KVLTl2ywu8d5SQpTJ1X7vDW_u_04xaqDQUdYKA"}}, clients.MockAuthenticate{RefreshError: errors.New("err")}, clients.MockAuthorize{}, http.StatusInternalServerError},
		{"can't save refreshed session", opts, http.MethodGet, &cryptutil.MockCipher{}, &sessions.MockSessionStore{SaveError: errors.New("err"), Session: &sessions.SessionState{Email: "user@test.example", IDToken: "eyJhbGciOiJSUzI1NiIsImtpZCI6IjA3YTA4MjgzOWYyZTcxYTliZjZjNTk2OTk2Yjk0NzM5Nzg1YWZkYzMiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiI4NTE4NzcwODIwNTktYmZna3BqMDlub29nN2FzM2dwYzN0N3I2bjlzamJnczYuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI4NTE4NzcwODIwNTktYmZna3BqMDlub29nN2FzM2dwYzN0N3I2bjlzamJnczYuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMTE0MzI2NTU5NzcyNzMxNTAzMDgiLCJoZCI6InBvbWVyaXVtLmlvIiwiZW1haWwiOiJiZGRAcG9tZXJpdW0uaW8iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiYXRfaGFzaCI6IlppQ1g0WndDYl9tcUVxM2xnbmFZRHciLCJuYW1lIjoiQm9iYnkgRGVTaW1vbmUiLCJwaWN0dXJlIjoiaHR0cHM6Ly9saDMuZ29vZ2xldXNlcmNvbnRlbnQuY29tLy1PX1BzRTlILTgzRS9BQUFBQUFBQUFBSS9BQUFBQUFBQUFBQS9BQ0hpM3JjQ0U0SFRLVDBhQk1pUFVfOEZfVXFOQ3F6RTBRL3M5Ni1jL3Bob3RvLmpwZyIsImdpdmVuX25hbWUiOiJCb2JieSIsImZhbWlseV9uYW1lIjoiRGVTaW1vbmUiLCJsb2NhbGUiOiJlbiIsImlhdCI6MTU1ODY1NDEzNywiZXhwIjoxNTU4NjU3NzM3fQ.Flah31XfqmPhWYh2rJ-6rtowmSQFgp6HqDf1rpS38Wo0DXnIYmXxEQVLanDNV62Z0sLhUk1QO9NqoSgA3NscM-Ww-JsqU80oKnWcMYweUb_KU0kfHyTiUB0iEHMqu6tXn5dA_dIaPnL5oorXZ_gG4sooRxBZrDkaNAjRINLciKDQkUTVaNfnM6IBZ_pWDPd2lWGtj8h8sEIe2PIiH73Z2VLlXz8kw60VTPsi9U2zrF0ZJ9MfRGJhceQ58vW2ZlFfXJixgvbOZjKmcRv8NaJDIUss48l0Bsya6icZ0l1ZK-sAiFr0KVLTl2ywu8d5SQpTJ1X7vDW_u_04xaqDQUdYKA"}}, clients.MockAuthenticate{}, clients.MockAuthorize{}, http.StatusInternalServerError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := New(tt.options)
			if err != nil {
				t.Fatal(err)
			}
			p.cipher = tt.cipher
			p.sessionStore = tt.session
			p.AuthenticateClient = tt.authenticator
			p.AuthorizeClient = tt.authorizer

			r := httptest.NewRequest(tt.method, "/", nil)
			w := httptest.NewRecorder()
			p.Refresh(w, r)
			if status := w.Code; status != tt.wantStatus {
				t.Errorf("status code: got %v want %v", status, tt.wantStatus)
				// t.Errorf("\n%+v", w.Body.String())
				t.Errorf("\n%+v", opts)
			}
		})
	}
}

func TestProxy_Impersonate(t *testing.T) {
	opts := testOptions()

	tests := []struct {
		name          string
		malformed     bool
		options       config.Options
		method        string
		email         string
		groups        string
		csrf          string
		cipher        cryptutil.Cipher
		sessionStore  sessions.SessionStore
		csrfStore     sessions.CSRFStore
		authenticator clients.Authenticator
		authorizer    clients.Authorizer
		wantStatus    int
	}{
		{"good", false, opts, http.MethodPost, "user@blah.com", "", "", &cryptutil.MockCipher{}, &sessions.MockSessionStore{Session: &sessions.SessionState{Email: "user@test.example", IDToken: ""}}, &sessions.MockCSRFStore{Cookie: &http.Cookie{Value: "csrf"}}, clients.MockAuthenticate{}, clients.MockAuthorize{IsAdminResponse: true}, http.StatusFound},
		{"session load error", false, opts, http.MethodPost, "user@blah.com", "", "", &cryptutil.MockCipher{}, &sessions.MockSessionStore{LoadError: errors.New("err"), Session: &sessions.SessionState{Email: "user@test.example", IDToken: ""}}, &sessions.MockCSRFStore{Cookie: &http.Cookie{Value: "csrf"}}, clients.MockAuthenticate{}, clients.MockAuthorize{IsAdminResponse: true}, http.StatusInternalServerError},
		{"non admin users rejected", false, opts, http.MethodPost, "user@blah.com", "", "", &cryptutil.MockCipher{}, &sessions.MockSessionStore{Session: &sessions.SessionState{Email: "user@test.example", IDToken: ""}}, &sessions.MockCSRFStore{Cookie: &http.Cookie{Value: "csrf"}}, clients.MockAuthenticate{}, clients.MockAuthorize{IsAdminResponse: false}, http.StatusForbidden},
		{"non admin users rejected on error", false, opts, http.MethodPost, "user@blah.com", "", "", &cryptutil.MockCipher{}, &sessions.MockSessionStore{Session: &sessions.SessionState{Email: "user@test.example", IDToken: ""}}, &sessions.MockCSRFStore{Cookie: &http.Cookie{Value: "csrf"}}, clients.MockAuthenticate{}, clients.MockAuthorize{IsAdminResponse: true, IsAdminError: errors.New("err")}, http.StatusForbidden},
		{"csrf from store retrieve failure", false, opts, http.MethodPost, "user@blah.com", "", "", &cryptutil.MockCipher{}, &sessions.MockSessionStore{Session: &sessions.SessionState{Email: "user@test.example", IDToken: ""}}, &sessions.MockCSRFStore{Cookie: &http.Cookie{Value: "csrf"}, GetError: errors.New("err")}, clients.MockAuthenticate{}, clients.MockAuthorize{IsAdminResponse: true}, http.StatusBadRequest},
		{"can't decrypt csrf value", false, opts, http.MethodPost, "user@blah.com", "", "", &cryptutil.MockCipher{UnmarshalError: errors.New("err")}, &sessions.MockSessionStore{Session: &sessions.SessionState{Email: "user@test.example", IDToken: ""}}, &sessions.MockCSRFStore{Cookie: &http.Cookie{Value: "csrf"}}, clients.MockAuthenticate{}, clients.MockAuthorize{IsAdminResponse: true}, http.StatusInternalServerError},
		{"decrypted csrf mismatch", false, opts, http.MethodPost, "user@blah.com", "", "CSRF!", &cryptutil.MockCipher{}, &sessions.MockSessionStore{Session: &sessions.SessionState{Email: "user@test.example", IDToken: ""}}, &sessions.MockCSRFStore{Cookie: &http.Cookie{Value: "csrf"}}, clients.MockAuthenticate{}, clients.MockAuthorize{IsAdminResponse: true}, http.StatusForbidden},
		{"save session failure", false, opts, http.MethodPost, "user@blah.com", "", "", &cryptutil.MockCipher{}, &sessions.MockSessionStore{SaveError: errors.New("err"), Session: &sessions.SessionState{Email: "user@test.example", IDToken: ""}}, &sessions.MockCSRFStore{Cookie: &http.Cookie{Value: "csrf"}}, clients.MockAuthenticate{}, clients.MockAuthorize{IsAdminResponse: true}, http.StatusInternalServerError},
		{"malformed", true, opts, http.MethodPost, "user@blah.com", "", "", &cryptutil.MockCipher{}, &sessions.MockSessionStore{Session: &sessions.SessionState{Email: "user@test.example", IDToken: ""}}, &sessions.MockCSRFStore{Cookie: &http.Cookie{Value: "csrf"}}, clients.MockAuthenticate{}, clients.MockAuthorize{IsAdminResponse: true}, http.StatusBadRequest},
		{"groups", false, opts, http.MethodPost, "user@blah.com", "group1,group2", "", &cryptutil.MockCipher{}, &sessions.MockSessionStore{Session: &sessions.SessionState{Email: "user@test.example", IDToken: ""}}, &sessions.MockCSRFStore{Cookie: &http.Cookie{Value: "csrf"}}, clients.MockAuthenticate{}, clients.MockAuthorize{IsAdminResponse: true}, http.StatusFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := New(tt.options)
			if err != nil {
				t.Fatal(err)
			}
			p.cipher = tt.cipher
			p.sessionStore = tt.sessionStore
			p.csrfStore = tt.csrfStore
			p.AuthenticateClient = tt.authenticator
			p.AuthorizeClient = tt.authorizer
			postForm := url.Values{}
			postForm.Add("email", tt.email)
			postForm.Add("group", tt.groups)
			postForm.Set("csrf", tt.csrf)
			uri := &url.URL{Path: "/"}
			if tt.malformed {
				uri.RawQuery = "email=%zzzzz"
			}
			r := httptest.NewRequest(tt.method, uri.String(), bytes.NewBufferString(postForm.Encode()))

			r.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
			w := httptest.NewRecorder()
			p.Impersonate(w, r)
			if status := w.Code; status != tt.wantStatus {
				t.Errorf("status code: got %v want %v", status, tt.wantStatus)
				// t.Errorf("\n%+v", w.Body.String())
				t.Errorf("\n%+v", opts)
			}
		})
	}
}

func TestProxy_OAuthCallback(t *testing.T) {
	tests := []struct {
		name          string
		csrf          sessions.MockCSRFStore
		session       sessions.MockSessionStore
		authenticator clients.MockAuthenticate
		params        map[string]string
		wantCode      int
	}{
		{"good", sessions.MockCSRFStore{ResponseCSRF: "ok", GetError: nil, Cookie: &http.Cookie{Name: "something_csrf", Value: "csrf_state"}}, sessions.MockSessionStore{Session: &sessions.SessionState{AccessToken: "AccessToken", RefreshToken: "RefreshToken", RefreshDeadline: time.Now().Add(-10 * time.Second)}}, clients.MockAuthenticate{RedeemResponse: &sessions.SessionState{AccessToken: "AccessToken", RefreshToken: "RefreshToken"}}, map[string]string{"code": "code", "state": "state"}, http.StatusFound},
		{"error", sessions.MockCSRFStore{ResponseCSRF: "ok", GetError: nil, Cookie: &http.Cookie{Name: "something_csrf", Value: "csrf_state"}}, sessions.MockSessionStore{Session: &sessions.SessionState{AccessToken: "AccessToken", RefreshToken: "RefreshToken", RefreshDeadline: time.Now().Add(-10 * time.Second)}}, clients.MockAuthenticate{RedeemResponse: &sessions.SessionState{AccessToken: "AccessToken", RefreshToken: "RefreshToken"}}, map[string]string{"error": "some error"}, http.StatusBadRequest},
		{"state err", sessions.MockCSRFStore{ResponseCSRF: "ok", GetError: nil, Cookie: &http.Cookie{Name: "something_csrf", Value: "csrf_state"}}, sessions.MockSessionStore{Session: &sessions.SessionState{AccessToken: "AccessToken", RefreshToken: "RefreshToken", RefreshDeadline: time.Now().Add(-10 * time.Second)}}, clients.MockAuthenticate{RedeemResponse: &sessions.SessionState{AccessToken: "AccessToken", RefreshToken: "RefreshToken"}}, map[string]string{"code": "code", "state": "error"}, http.StatusInternalServerError},
		{"csrf err", sessions.MockCSRFStore{GetError: errors.New("error")}, sessions.MockSessionStore{Session: &sessions.SessionState{AccessToken: "AccessToken", RefreshToken: "RefreshToken", RefreshDeadline: time.Now().Add(-10 * time.Second)}}, clients.MockAuthenticate{RedeemResponse: &sessions.SessionState{AccessToken: "AccessToken", RefreshToken: "RefreshToken"}}, map[string]string{"code": "code", "state": "state"}, http.StatusBadRequest},
		{"unmarshal err", sessions.MockCSRFStore{Cookie: &http.Cookie{Name: "something_csrf", Value: "unmarshal error"}}, sessions.MockSessionStore{Session: &sessions.SessionState{AccessToken: "AccessToken", RefreshToken: "RefreshToken", RefreshDeadline: time.Now().Add(-10 * time.Second)}}, clients.MockAuthenticate{RedeemResponse: &sessions.SessionState{AccessToken: "AccessToken", RefreshToken: "RefreshToken"}}, map[string]string{"code": "code", "state": "state"}, http.StatusInternalServerError},
		{"malformed", sessions.MockCSRFStore{ResponseCSRF: "ok", GetError: nil, Cookie: &http.Cookie{Name: "something_csrf", Value: "csrf_state"}}, sessions.MockSessionStore{Session: &sessions.SessionState{AccessToken: "AccessToken", RefreshToken: "RefreshToken", RefreshDeadline: time.Now().Add(-10 * time.Second)}}, clients.MockAuthenticate{RedeemResponse: &sessions.SessionState{AccessToken: "AccessToken", RefreshToken: "RefreshToken"}}, map[string]string{"code": "code", "state": "state"}, http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proxy, err := New(testOptions())
			if err != nil {
				t.Fatal(err)
			}
			proxy.sessionStore = &tt.session
			proxy.csrfStore = tt.csrf
			proxy.AuthenticateClient = tt.authenticator
			proxy.cipher = mockCipher{}
			// proxy.Csrf
			req := httptest.NewRequest(http.MethodPost, "/.pomerium/callback", nil)
			q := req.URL.Query()
			for k, v := range tt.params {
				q.Add(k, v)
			}
			req.URL.RawQuery = q.Encode()
			if tt.name == "malformed" {
				req.URL.RawQuery = "email=%zzzzz"
			}
			w := httptest.NewRecorder()
			proxy.OAuthCallback(w, req)
			if status := w.Code; status != tt.wantCode {
				t.Errorf("handler returned wrong status code: got %v want %v", status, tt.wantCode)
			}
		})
	}

}
