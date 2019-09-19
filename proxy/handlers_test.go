package proxy

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/pomerium/pomerium/internal/config"
	"github.com/pomerium/pomerium/internal/cryptutil"
	"github.com/pomerium/pomerium/internal/identity"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/proxy/clients"
)

func TestProxy_RobotsTxt(t *testing.T) {
	proxy := Proxy{}
	req := httptest.NewRequest(http.MethodGet, "/robots.txt", nil)
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

func TestProxy_Signout(t *testing.T) {
	opts := testOptions(t)
	err := ValidateOptions(opts)
	if err != nil {
		t.Fatal(err)
	}
	proxy, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/.pomerium/sign_out", nil)
	rr := httptest.NewRecorder()
	proxy.SignOut(rr, req)
	if status := rr.Code; status != http.StatusFound {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusFound)
	}
	body := rr.Body.String()
	want := (proxy.authenticateURL.String())
	if !strings.Contains(body, want) {
		t.Errorf("handler returned unexpected body: got %v want %s ", body, want)
	}
}

func TestProxy_authenticate(t *testing.T) {
	proxy, err := New(testOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/oauth-start", nil)

	rr := httptest.NewRecorder()
	proxy.authenticate(rr, req)
	// expect oauth redirect
	if status := rr.Code; status != http.StatusFound {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusFound)
	}
	// expected url
	expected := `<a href="https://authenticate.example/.pomerium/sign_in`
	body := rr.Body.String()
	if !strings.HasPrefix(body, expected) {
		t.Errorf("handler returned unexpected body: got %v want %v", body, expected)
	}
}

func TestProxy_Handler(t *testing.T) {
	proxy, err := New(testOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	h := proxy.Handler()
	if h == nil {
		t.Error("handler cannot be nil")
	}
	mux := http.NewServeMux()
	mux.Handle("/", h)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404 route not found for empty route")
	}
}

func TestProxy_router(t *testing.T) {
	testPolicy := config.Policy{From: "https://corp.example.com", To: "https://example.com"}
	if err := testPolicy.Validate(); err != nil {
		t.Fatal(err)
	}
	policies := []config.Policy{testPolicy}
	tests := []struct {
		name   string
		host   string
		mux    []config.Policy
		route  http.Handler
		wantOk bool
	}{
		{"good corp", "https://corp.example.com", policies, nil, true},
		{"good with slash", "https://corp.example.com/", policies, nil, true},
		{"good with path", "https://corp.example.com/123", policies, nil, true},
		{"no policies", "https://notcorp.example.com/123", []config.Policy{}, nil, false},
		{"bad corp", "https://notcorp.example.com/123", policies, nil, false},
		{"bad sub-sub", "https://notcorp.corp.example.com/123", policies, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := testOptions(t)
			opts.Policies = tt.mux
			p, err := New(opts)
			if err != nil {
				t.Fatal(err)
			}
			p.encoder = &cryptutil.MockEncoder{MarshalResponse: "foo"}

			req := httptest.NewRequest(http.MethodGet, tt.host, nil)
			_, ok := p.router(req)
			if ok != tt.wantOk {
				t.Errorf("Proxy.router() ok = %v, want %v", ok, tt.wantOk)
			}
		})
	}
}

func TestProxy_Proxy(t *testing.T) {
	goodSession := &sessions.State{
		AccessToken:     "AccessToken",
		RefreshToken:    "RefreshToken",
		RefreshDeadline: time.Now().Add(20 * time.Second),
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		fmt.Fprintln(w, "RVSI FILIVS CAISAR")
		w.WriteHeader(http.StatusOK)

	}))
	defer ts.Close()

	opts := testOptionsTestServer(t, ts.URL)
	optsCORS := testOptionsWithCORS(t, ts.URL)
	optsPublic := testOptionsWithPublicAccess(t, ts.URL)
	optsNoPolicies := testOptionsWithEmptyPolicies(t, ts.URL)

	defaultHeaders, goodCORSHeaders, badCORSHeaders, headersWs := http.Header{}, http.Header{}, http.Header{}, http.Header{}
	goodCORSHeaders.Set("origin", "anything")
	goodCORSHeaders.Set("access-control-request-method", "anything")
	// missing "Origin"
	badCORSHeaders.Set("access-control-request-method", "anything")
	headersWs.Set("Connection", "Upgrade")
	headersWs.Set("Upgrade", "websocket")

	tests := []struct {
		name       string
		options    config.Options
		method     string
		header     http.Header
		host       string
		session    sessions.SessionStore
		authorizer clients.Authorizer
		wantStatus int
	}{
		{"good", opts, http.MethodGet, defaultHeaders, "https://httpbin.corp.example/", &sessions.MockSessionStore{Session: &sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", RefreshDeadline: time.Now().Add(20 * time.Second)}}, clients.MockAuthorize{AuthorizeResponse: true}, http.StatusOK},
		{"good cors preflight", optsCORS, http.MethodOptions, goodCORSHeaders, "https://httpbin.corp.example/", &sessions.MockSessionStore{Session: goodSession}, clients.MockAuthorize{AuthorizeResponse: false}, http.StatusOK},
		{"good email impersonation", opts, http.MethodGet, defaultHeaders, "https://httpbin.corp.example/", &sessions.MockSessionStore{Session: &sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", RefreshDeadline: time.Now().Add(10 * time.Second), ImpersonateEmail: "test@user.example"}}, clients.MockAuthorize{AuthorizeResponse: true}, http.StatusOK},
		{"good group impersonation", opts, http.MethodGet, defaultHeaders, "https://httpbin.corp.example/", &sessions.MockSessionStore{Session: &sessions.State{AccessToken: "AccessToken", RefreshToken: "RefreshToken", RefreshDeadline: time.Now().Add(10 * time.Second), ImpersonateGroups: []string{"group1", "group2"}}}, clients.MockAuthorize{AuthorizeResponse: true}, http.StatusOK},
		// same request as above, but with cors_allow_preflight=false in the policy
		{"valid cors, but not allowed", opts, http.MethodOptions, goodCORSHeaders, "https://httpbin.corp.example/", &sessions.MockSessionStore{Session: goodSession}, clients.MockAuthorize{AuthorizeResponse: false}, http.StatusForbidden},
		// cors allowed, but the request is missing proper headers
		{"invalid cors headers", optsCORS, http.MethodOptions, badCORSHeaders, "https://httpbin.corp.example/", &sessions.MockSessionStore{Session: goodSession}, clients.MockAuthorize{AuthorizeResponse: false}, http.StatusForbidden},
		// redirect to start auth process
		{"unknown host", opts, http.MethodGet, defaultHeaders, "https://nothttpbin.corp.example", &sessions.MockSessionStore{Session: goodSession}, clients.MockAuthorize{AuthorizeResponse: true}, http.StatusNotFound},
		{"user not authorized", opts, http.MethodGet, defaultHeaders, "https://httpbin.corp.example/", &sessions.MockSessionStore{Session: goodSession}, clients.MockAuthorize{AuthorizeResponse: false}, http.StatusForbidden},
		{"authorization call failed", opts, http.MethodGet, defaultHeaders, "https://httpbin.corp.example/", &sessions.MockSessionStore{Session: goodSession}, clients.MockAuthorize{AuthorizeError: errors.New("error")}, http.StatusInternalServerError},
		// authenticate errors
		{"session expired,redirect to authn", opts, http.MethodGet, defaultHeaders, "https://httpbin.corp.example/", &sessions.MockSessionStore{LoadError: sessions.ErrExpired}, clients.MockAuthorize{AuthorizeResponse: true}, http.StatusFound},
		{"public access", optsPublic, http.MethodGet, defaultHeaders, "https://httpbin.corp.example/", &sessions.MockSessionStore{Session: goodSession}, clients.MockAuthorize{AuthorizeResponse: false}, http.StatusOK},
		{"public access, but unknown host", optsPublic, http.MethodGet, defaultHeaders, "https://nothttpbin.corp.example", &sessions.MockSessionStore{Session: goodSession}, clients.MockAuthorize{AuthorizeResponse: false}, http.StatusNotFound},
		{"no http found (no session),redirect to authn", opts, http.MethodGet, defaultHeaders, "https://httpbin.corp.example/", &sessions.MockSessionStore{LoadError: http.ErrNoCookie}, clients.MockAuthorize{AuthorizeResponse: true}, http.StatusFound},
		{"No policies", optsNoPolicies, http.MethodGet, defaultHeaders, "https://httpbin.corp.example/", &sessions.MockSessionStore{Session: goodSession}, clients.MockAuthorize{AuthorizeResponse: true}, http.StatusNotFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateOptions(tt.options)
			if err != nil {
				t.Fatal(err)
			}
			p, err := New(tt.options)
			if err != nil {
				t.Fatal(err)
			}
			p.encoder = &cryptutil.MockEncoder{MarshalResponse: "foo"}
			p.sessionStore = tt.session
			p.AuthorizeClient = tt.authorizer
			r := httptest.NewRequest(tt.method, tt.host, nil)
			r.Header = tt.header
			r.Header.Set("Accept", "application/json")
			state, _ := tt.session.LoadSession(r)
			ctx := r.Context()
			ctx = sessions.NewContext(ctx, state, nil)
			r = r.WithContext(ctx)

			w := httptest.NewRecorder()
			p.Proxy(w, r)
			if status := w.Code; status != tt.wantStatus {
				t.Errorf("handler returned wrong status code: got %v want %v \n body %s", status, tt.wantStatus, w.Body.String())
			}

		})
	}
}

func TestProxy_UserDashboard(t *testing.T) {
	opts := testOptions(t)
	tests := []struct {
		name       string
		ctxError   error
		options    config.Options
		method     string
		cipher     cryptutil.SecureEncoder
		session    sessions.SessionStore
		authorizer clients.Authorizer

		wantAdminForm bool
		wantStatus    int
	}{
		{"good", nil, opts, http.MethodGet, &cryptutil.MockEncoder{}, &sessions.MockSessionStore{Session: &sessions.State{Email: "user@test.example", RefreshDeadline: time.Now().Add(10 * time.Second)}}, clients.MockAuthorize{}, false, http.StatusOK},
		{"session context error", errors.New("error"), opts, http.MethodGet, &cryptutil.MockEncoder{}, &sessions.MockSessionStore{Session: &sessions.State{Email: "user@test.example", RefreshDeadline: time.Now().Add(10 * time.Second)}}, clients.MockAuthorize{}, false, http.StatusInternalServerError},
		{"want admin form good admin authorization", nil, opts, http.MethodGet, &cryptutil.MockEncoder{}, &sessions.MockSessionStore{Session: &sessions.State{Email: "user@test.example", RefreshDeadline: time.Now().Add(10 * time.Second)}}, clients.MockAuthorize{IsAdminResponse: true}, true, http.StatusOK},
		{"is admin but authorization fails", nil, opts, http.MethodGet, &cryptutil.MockEncoder{}, &sessions.MockSessionStore{Session: &sessions.State{Email: "user@test.example", RefreshDeadline: time.Now().Add(10 * time.Second)}}, clients.MockAuthorize{IsAdminError: errors.New("err")}, false, http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := New(tt.options)
			if err != nil {
				t.Fatal(err)
			}
			p.encoder = tt.cipher
			p.sessionStore = tt.session
			p.AuthorizeClient = tt.authorizer

			r := httptest.NewRequest(tt.method, "/", nil)
			state, _ := tt.session.LoadSession(r)
			ctx := r.Context()
			ctx = sessions.NewContext(ctx, state, tt.ctxError)
			r = r.WithContext(ctx)

			r.Header.Set("Accept", "application/json")

			w := httptest.NewRecorder()
			p.UserDashboard(w, r)
			if status := w.Code; status != tt.wantStatus {
				t.Errorf("status code: got %v want %v", status, tt.wantStatus)
				t.Errorf("\n%+v", opts)
				t.Errorf("\n%+v", w.Body.String())

			}
			if adminForm := strings.Contains(w.Body.String(), "impersonate"); adminForm != tt.wantAdminForm {
				t.Errorf("wanted admin form  got %v want %v", adminForm, tt.wantAdminForm)
				t.Errorf("\n%+v", w.Body.String())
			}
		})
	}
}

func TestProxy_ForceRefresh(t *testing.T) {
	opts := testOptions(t)
	opts.RefreshCooldown = 0
	timeSinceError := testOptions(t)
	timeSinceError.RefreshCooldown = time.Duration(int(^uint(0) >> 1))

	tests := []struct {
		name       string
		ctxError   error
		options    config.Options
		method     string
		cipher     cryptutil.SecureEncoder
		session    sessions.SessionStore
		authorizer clients.Authorizer
		wantStatus int
	}{
		{"good", nil, opts, http.MethodGet, &cryptutil.MockEncoder{}, &sessions.MockSessionStore{Session: &sessions.State{Email: "user@test.example", IDToken: "eyJhbGciOiJSUzI1NiIsImtpZCI6IjA3YTA4MjgzOWYyZTcxYTliZjZjNTk2OTk2Yjk0NzM5Nzg1YWZkYzMiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiI4NTE4NzcwODIwNTktYmZna3BqMDlub29nN2FzM2dwYzN0N3I2bjlzamJnczYuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI4NTE4NzcwODIwNTktYmZna3BqMDlub29nN2FzM2dwYzN0N3I2bjlzamJnczYuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMTE0MzI2NTU5NzcyNzMxNTAzMDgiLCJoZCI6InBvbWVyaXVtLmlvIiwiZW1haWwiOiJiZGRAcG9tZXJpdW0uaW8iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiYXRfaGFzaCI6IlppQ1g0WndDYl9tcUVxM2xnbmFZRHciLCJuYW1lIjoiQm9iYnkgRGVTaW1vbmUiLCJwaWN0dXJlIjoiaHR0cHM6Ly9saDMuZ29vZ2xldXNlcmNvbnRlbnQuY29tLy1PX1BzRTlILTgzRS9BQUFBQUFBQUFBSS9BQUFBQUFBQUFBQS9BQ0hpM3JjQ0U0SFRLVDBhQk1pUFVfOEZfVXFOQ3F6RTBRL3M5Ni1jL3Bob3RvLmpwZyIsImdpdmVuX25hbWUiOiJCb2JieSIsImZhbWlseV9uYW1lIjoiRGVTaW1vbmUiLCJsb2NhbGUiOiJlbiIsImlhdCI6MTU1ODY1NDEzNywiZXhwIjoxNTU4NjU3NzM3fQ.Flah31XfqmPhWYh2rJ-6rtowmSQFgp6HqDf1rpS38Wo0DXnIYmXxEQVLanDNV62Z0sLhUk1QO9NqoSgA3NscM-Ww-JsqU80oKnWcMYweUb_KU0kfHyTiUB0iEHMqu6tXn5dA_dIaPnL5oorXZ_gG4sooRxBZrDkaNAjRINLciKDQkUTVaNfnM6IBZ_pWDPd2lWGtj8h8sEIe2PIiH73Z2VLlXz8kw60VTPsi9U2zrF0ZJ9MfRGJhceQ58vW2ZlFfXJixgvbOZjKmcRv8NaJDIUss48l0Bsya6icZ0l1ZK-sAiFr0KVLTl2ywu8d5SQpTJ1X7vDW_u_04xaqDQUdYKA"}}, clients.MockAuthorize{}, http.StatusFound},
		{"cannot load session", errors.New("error"), opts, http.MethodGet, &cryptutil.MockEncoder{}, &sessions.MockSessionStore{Session: &sessions.State{Email: "user@test.example", IDToken: "eyJhbGciOiJSUzI1NiIsImtpZCI6IjA3YTA4MjgzOWYyZTcxYTliZjZjNTk2OTk2Yjk0NzM5Nzg1YWZkYzMiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiI4NTE4NzcwODIwNTktYmZna3BqMDlub29nN2FzM2dwYzN0N3I2bjlzamJnczYuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI4NTE4NzcwODIwNTktYmZna3BqMDlub29nN2FzM2dwYzN0N3I2bjlzamJnczYuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMTE0MzI2NTU5NzcyNzMxNTAzMDgiLCJoZCI6InBvbWVyaXVtLmlvIiwiZW1haWwiOiJiZGRAcG9tZXJpdW0uaW8iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiYXRfaGFzaCI6IlppQ1g0WndDYl9tcUVxM2xnbmFZRHciLCJuYW1lIjoiQm9iYnkgRGVTaW1vbmUiLCJwaWN0dXJlIjoiaHR0cHM6Ly9saDMuZ29vZ2xldXNlcmNvbnRlbnQuY29tLy1PX1BzRTlILTgzRS9BQUFBQUFBQUFBSS9BQUFBQUFBQUFBQS9BQ0hpM3JjQ0U0SFRLVDBhQk1pUFVfOEZfVXFOQ3F6RTBRL3M5Ni1jL3Bob3RvLmpwZyIsImdpdmVuX25hbWUiOiJCb2JieSIsImZhbWlseV9uYW1lIjoiRGVTaW1vbmUiLCJsb2NhbGUiOiJlbiIsImlhdCI6MTU1ODY1NDEzNywiZXhwIjoxNTU4NjU3NzM3fQ.Flah31XfqmPhWYh2rJ-6rtowmSQFgp6HqDf1rpS38Wo0DXnIYmXxEQVLanDNV62Z0sLhUk1QO9NqoSgA3NscM-Ww-JsqU80oKnWcMYweUb_KU0kfHyTiUB0iEHMqu6tXn5dA_dIaPnL5oorXZ_gG4sooRxBZrDkaNAjRINLciKDQkUTVaNfnM6IBZ_pWDPd2lWGtj8h8sEIe2PIiH73Z2VLlXz8kw60VTPsi9U2zrF0ZJ9MfRGJhceQ58vW2ZlFfXJixgvbOZjKmcRv8NaJDIUss48l0Bsya6icZ0l1ZK-sAiFr0KVLTl2ywu8d5SQpTJ1X7vDW_u_04xaqDQUdYKA"}}, clients.MockAuthorize{}, http.StatusInternalServerError},
		{"bad id token", nil, opts, http.MethodGet, &cryptutil.MockEncoder{}, &sessions.MockSessionStore{Session: &sessions.State{RefreshDeadline: time.Now().Add(10 * time.Second), Email: "user@test.example", IDToken: "bad"}}, clients.MockAuthorize{}, http.StatusInternalServerError},
		{"issue date too soon", nil, timeSinceError, http.MethodGet, &cryptutil.MockEncoder{}, &sessions.MockSessionStore{Session: &sessions.State{RefreshDeadline: time.Now().Add(10 * time.Second), Email: "user@test.example", IDToken: "eyJhbGciOiJSUzI1NiIsImtpZCI6IjA3YTA4MjgzOWYyZTcxYTliZjZjNTk2OTk2Yjk0NzM5Nzg1YWZkYzMiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiI4NTE4NzcwODIwNTktYmZna3BqMDlub29nN2FzM2dwYzN0N3I2bjlzamJnczYuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI4NTE4NzcwODIwNTktYmZna3BqMDlub29nN2FzM2dwYzN0N3I2bjlzamJnczYuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMTE0MzI2NTU5NzcyNzMxNTAzMDgiLCJoZCI6InBvbWVyaXVtLmlvIiwiZW1haWwiOiJiZGRAcG9tZXJpdW0uaW8iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiYXRfaGFzaCI6IlppQ1g0WndDYl9tcUVxM2xnbmFZRHciLCJuYW1lIjoiQm9iYnkgRGVTaW1vbmUiLCJwaWN0dXJlIjoiaHR0cHM6Ly9saDMuZ29vZ2xldXNlcmNvbnRlbnQuY29tLy1PX1BzRTlILTgzRS9BQUFBQUFBQUFBSS9BQUFBQUFBQUFBQS9BQ0hpM3JjQ0U0SFRLVDBhQk1pUFVfOEZfVXFOQ3F6RTBRL3M5Ni1jL3Bob3RvLmpwZyIsImdpdmVuX25hbWUiOiJCb2JieSIsImZhbWlseV9uYW1lIjoiRGVTaW1vbmUiLCJsb2NhbGUiOiJlbiIsImlhdCI6MTU1ODY1NDEzNywiZXhwIjoxNTU4NjU3NzM3fQ.Flah31XfqmPhWYh2rJ-6rtowmSQFgp6HqDf1rpS38Wo0DXnIYmXxEQVLanDNV62Z0sLhUk1QO9NqoSgA3NscM-Ww-JsqU80oKnWcMYweUb_KU0kfHyTiUB0iEHMqu6tXn5dA_dIaPnL5oorXZ_gG4sooRxBZrDkaNAjRINLciKDQkUTVaNfnM6IBZ_pWDPd2lWGtj8h8sEIe2PIiH73Z2VLlXz8kw60VTPsi9U2zrF0ZJ9MfRGJhceQ58vW2ZlFfXJixgvbOZjKmcRv8NaJDIUss48l0Bsya6icZ0l1ZK-sAiFr0KVLTl2ywu8d5SQpTJ1X7vDW_u_04xaqDQUdYKA"}}, clients.MockAuthorize{}, http.StatusBadRequest},
		{"refresh failure", nil, opts, http.MethodGet, &cryptutil.MockEncoder{}, &sessions.MockSessionStore{Session: &sessions.State{Email: "user@test.example", IDToken: "eyJhbGciOiJSUzI1NiIsImtpZCI6IjA3YTA4MjgzOWYyZTcxYTliZjZjNTk2OTk2Yjk0NzM5Nzg1YWZkYzMiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiI4NTE4NzcwODIwNTktYmZna3BqMDlub29nN2FzM2dwYzN0N3I2bjlzamJnczYuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI4NTE4NzcwODIwNTktYmZna3BqMDlub29nN2FzM2dwYzN0N3I2bjlzamJnczYuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMTE0MzI2NTU5NzcyNzMxNTAzMDgiLCJoZCI6InBvbWVyaXVtLmlvIiwiZW1haWwiOiJiZGRAcG9tZXJpdW0uaW8iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiYXRfaGFzaCI6IlppQ1g0WndDYl9tcUVxM2xnbmFZRHciLCJuYW1lIjoiQm9iYnkgRGVTaW1vbmUiLCJwaWN0dXJlIjoiaHR0cHM6Ly9saDMuZ29vZ2xldXNlcmNvbnRlbnQuY29tLy1PX1BzRTlILTgzRS9BQUFBQUFBQUFBSS9BQUFBQUFBQUFBQS9BQ0hpM3JjQ0U0SFRLVDBhQk1pUFVfOEZfVXFOQ3F6RTBRL3M5Ni1jL3Bob3RvLmpwZyIsImdpdmVuX25hbWUiOiJCb2JieSIsImZhbWlseV9uYW1lIjoiRGVTaW1vbmUiLCJsb2NhbGUiOiJlbiIsImlhdCI6MTU1ODY1NDEzNywiZXhwIjoxNTU4NjU3NzM3fQ.Flah31XfqmPhWYh2rJ-6rtowmSQFgp6HqDf1rpS38Wo0DXnIYmXxEQVLanDNV62Z0sLhUk1QO9NqoSgA3NscM-Ww-JsqU80oKnWcMYweUb_KU0kfHyTiUB0iEHMqu6tXn5dA_dIaPnL5oorXZ_gG4sooRxBZrDkaNAjRINLciKDQkUTVaNfnM6IBZ_pWDPd2lWGtj8h8sEIe2PIiH73Z2VLlXz8kw60VTPsi9U2zrF0ZJ9MfRGJhceQ58vW2ZlFfXJixgvbOZjKmcRv8NaJDIUss48l0Bsya6icZ0l1ZK-sAiFr0KVLTl2ywu8d5SQpTJ1X7vDW_u_04xaqDQUdYKA"}}, clients.MockAuthorize{}, http.StatusFound},
		{"can't save refreshed session", nil, opts, http.MethodGet, &cryptutil.MockEncoder{}, &sessions.MockSessionStore{SaveError: errors.New("err"), Session: &sessions.State{Email: "user@test.example", IDToken: "eyJhbGciOiJSUzI1NiIsImtpZCI6IjA3YTA4MjgzOWYyZTcxYTliZjZjNTk2OTk2Yjk0NzM5Nzg1YWZkYzMiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiI4NTE4NzcwODIwNTktYmZna3BqMDlub29nN2FzM2dwYzN0N3I2bjlzamJnczYuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI4NTE4NzcwODIwNTktYmZna3BqMDlub29nN2FzM2dwYzN0N3I2bjlzamJnczYuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMTE0MzI2NTU5NzcyNzMxNTAzMDgiLCJoZCI6InBvbWVyaXVtLmlvIiwiZW1haWwiOiJiZGRAcG9tZXJpdW0uaW8iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiYXRfaGFzaCI6IlppQ1g0WndDYl9tcUVxM2xnbmFZRHciLCJuYW1lIjoiQm9iYnkgRGVTaW1vbmUiLCJwaWN0dXJlIjoiaHR0cHM6Ly9saDMuZ29vZ2xldXNlcmNvbnRlbnQuY29tLy1PX1BzRTlILTgzRS9BQUFBQUFBQUFBSS9BQUFBQUFBQUFBQS9BQ0hpM3JjQ0U0SFRLVDBhQk1pUFVfOEZfVXFOQ3F6RTBRL3M5Ni1jL3Bob3RvLmpwZyIsImdpdmVuX25hbWUiOiJCb2JieSIsImZhbWlseV9uYW1lIjoiRGVTaW1vbmUiLCJsb2NhbGUiOiJlbiIsImlhdCI6MTU1ODY1NDEzNywiZXhwIjoxNTU4NjU3NzM3fQ.Flah31XfqmPhWYh2rJ-6rtowmSQFgp6HqDf1rpS38Wo0DXnIYmXxEQVLanDNV62Z0sLhUk1QO9NqoSgA3NscM-Ww-JsqU80oKnWcMYweUb_KU0kfHyTiUB0iEHMqu6tXn5dA_dIaPnL5oorXZ_gG4sooRxBZrDkaNAjRINLciKDQkUTVaNfnM6IBZ_pWDPd2lWGtj8h8sEIe2PIiH73Z2VLlXz8kw60VTPsi9U2zrF0ZJ9MfRGJhceQ58vW2ZlFfXJixgvbOZjKmcRv8NaJDIUss48l0Bsya6icZ0l1ZK-sAiFr0KVLTl2ywu8d5SQpTJ1X7vDW_u_04xaqDQUdYKA"}}, clients.MockAuthorize{}, http.StatusInternalServerError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := New(tt.options)
			if err != nil {
				t.Fatal(err)
			}
			p.encoder = tt.cipher
			p.sessionStore = tt.session
			p.AuthorizeClient = tt.authorizer

			r := httptest.NewRequest(tt.method, "/", nil)
			state, _ := tt.session.LoadSession(r)
			ctx := r.Context()
			ctx = sessions.NewContext(ctx, state, tt.ctxError)
			r = r.WithContext(ctx)
			r.Header.Set("Accept", "application/json")

			w := httptest.NewRecorder()
			p.ForceRefresh(w, r)
			if status := w.Code; status != tt.wantStatus {
				t.Errorf("status code: got %v want %v", status, tt.wantStatus)
				t.Errorf("\n%+v", opts)
			}
		})
	}
}

func TestProxy_Impersonate(t *testing.T) {
	t.Parallel()
	opts := testOptions(t)
	tests := []struct {
		name         string
		malformed    bool
		options      config.Options
		ctxError     error
		method       string
		email        string
		groups       string
		csrf         string
		cipher       cryptutil.SecureEncoder
		sessionStore sessions.SessionStore
		authorizer   clients.Authorizer
		wantStatus   int
	}{
		{"good", false, opts, nil, http.MethodPost, "user@blah.com", "", "", &cryptutil.MockEncoder{}, &sessions.MockSessionStore{Session: &sessions.State{Email: "user@test.example", IDToken: ""}}, clients.MockAuthorize{IsAdminResponse: true}, http.StatusFound},
		{"good", false, opts, errors.New("error"), http.MethodPost, "user@blah.com", "", "", &cryptutil.MockEncoder{}, &sessions.MockSessionStore{Session: &sessions.State{Email: "user@test.example", IDToken: ""}}, clients.MockAuthorize{IsAdminResponse: true}, http.StatusInternalServerError},
		{"session load error", false, opts, nil, http.MethodPost, "user@blah.com", "", "", &cryptutil.MockEncoder{}, &sessions.MockSessionStore{LoadError: errors.New("err"), Session: &sessions.State{Email: "user@test.example", IDToken: ""}}, clients.MockAuthorize{IsAdminResponse: true}, http.StatusFound},
		{"non admin users rejected", false, opts, nil, http.MethodPost, "user@blah.com", "", "", &cryptutil.MockEncoder{}, &sessions.MockSessionStore{Session: &sessions.State{RefreshDeadline: time.Now().Add(10 * time.Second), Email: "user@test.example", IDToken: ""}}, clients.MockAuthorize{IsAdminResponse: false}, http.StatusForbidden},
		{"non admin users rejected on error", false, opts, nil, http.MethodPost, "user@blah.com", "", "", &cryptutil.MockEncoder{}, &sessions.MockSessionStore{Session: &sessions.State{RefreshDeadline: time.Now().Add(10 * time.Second), Email: "user@test.example", IDToken: ""}}, clients.MockAuthorize{IsAdminResponse: true, IsAdminError: errors.New("err")}, http.StatusForbidden},
		{"save session failure", false, opts, nil, http.MethodPost, "user@blah.com", "", "", &cryptutil.MockEncoder{}, &sessions.MockSessionStore{SaveError: errors.New("err"), Session: &sessions.State{RefreshDeadline: time.Now().Add(10 * time.Second), Email: "user@test.example", IDToken: ""}}, clients.MockAuthorize{IsAdminResponse: true}, http.StatusInternalServerError},
		{"groups", false, opts, nil, http.MethodPost, "user@blah.com", "group1,group2", "", &cryptutil.MockEncoder{}, &sessions.MockSessionStore{Session: &sessions.State{RefreshDeadline: time.Now().Add(10 * time.Second), Email: "user@test.example", IDToken: ""}}, clients.MockAuthorize{IsAdminResponse: true}, http.StatusFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := New(tt.options)
			if err != nil {
				t.Fatal(err)
			}
			p.encoder = tt.cipher
			p.sessionStore = tt.sessionStore
			p.AuthorizeClient = tt.authorizer
			postForm := url.Values{}
			postForm.Add("email", tt.email)
			postForm.Add("group", tt.groups)
			postForm.Set("csrf", tt.csrf)
			uri := &url.URL{Path: "/"}

			r := httptest.NewRequest(tt.method, uri.String(), bytes.NewBufferString(postForm.Encode()))
			state, _ := tt.sessionStore.LoadSession(r)
			ctx := r.Context()
			ctx = sessions.NewContext(ctx, state, tt.ctxError)
			r = r.WithContext(ctx)

			r.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
			w := httptest.NewRecorder()
			p.Impersonate(w, r)
			if status := w.Code; status != tt.wantStatus {
				t.Errorf("status code: got %v want %v", status, tt.wantStatus)
				t.Errorf("\n%+v", opts)
			}
		})
	}
}

func TestProxy_SignOut(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		verb        string
		redirectURL string
		wantStatus  int
	}{
		{"good post", http.MethodPost, "https://test.example", http.StatusFound},
		{"good get", http.MethodGet, "https://test.example", http.StatusFound},
		{"good empty default", http.MethodGet, "", http.StatusFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := testOptions(t)
			p, err := New(opts)
			if err != nil {
				t.Fatal(err)
			}
			postForm := url.Values{}
			postForm.Add("redirect_uri", tt.redirectURL)
			uri := &url.URL{Path: "/"}

			query, _ := url.ParseQuery(uri.RawQuery)
			if tt.verb == http.MethodGet {
				query.Add("redirect_uri", tt.redirectURL)
				uri.RawQuery = query.Encode()
			}
			r := httptest.NewRequest(tt.verb, uri.String(), bytes.NewBufferString(postForm.Encode()))
			w := httptest.NewRecorder()
			if tt.verb == http.MethodPost {
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
			}
			p.SignOut(w, r)
			if status := w.Code; status != tt.wantStatus {
				t.Errorf("status code: got %v want %v", status, tt.wantStatus)
			}

		})
	}
}
func uriParseHelper(s string) *url.URL {
	uri, _ := url.Parse(s)
	return uri
}
func TestProxy_VerifySession(t *testing.T) {
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
		{"expired", &sessions.MockSessionStore{Session: &sessions.State{Email: "user@test.example", RefreshDeadline: time.Now().Add(-10 * time.Second)}}, nil, identity.MockProvider{}, http.StatusFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			a := Proxy{
				SharedKey:             "80ldlrU2d7w+wVpKNfevk6fmb8otEx6CqOfshj2LwhQ=",
				cookieSecret:          []byte("80ldlrU2d7w+wVpKNfevk6fmb8otEx6CqOfshj2LwhQ="),
				authenticateURL:       uriParseHelper("https://authenticate.corp.example"),
				authenticateSigninURL: uriParseHelper("https://authenticate.corp.example/sign_in"),
				sessionStore:          tt.session,
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
