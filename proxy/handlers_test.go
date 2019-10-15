package proxy // import "github.com/pomerium/pomerium/proxy"

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

	"github.com/google/go-cmp/cmp"
	"github.com/pomerium/pomerium/internal/config"
	"github.com/pomerium/pomerium/internal/cryptutil"
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
	uri, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return uri
}
func TestProxy_VerifyWithMiddleware(t *testing.T) {
	t.Parallel()
	opts := testOptions(t)
	tests := []struct {
		name      string
		options   config.Options
		ctxError  error
		method    string
		qp        string
		path      string
		verifyURI string

		cipher       cryptutil.SecureEncoder
		sessionStore sessions.SessionStore
		authorizer   clients.Authorizer
		wantStatus   int
		wantBody     string
	}{
		{"good", opts, nil, http.MethodGet, "", "/", "https://some.domain.example", &cryptutil.MockEncoder{}, &sessions.MockSessionStore{Session: &sessions.State{Email: "user@test.example", RefreshDeadline: time.Now().Add(10 * time.Second)}}, clients.MockAuthorize{AuthorizeResponse: true}, http.StatusOK, ""},
		{"good verify only", opts, nil, http.MethodGet, "", "/verify", "https://some.domain.example", &cryptutil.MockEncoder{}, &sessions.MockSessionStore{Session: &sessions.State{Email: "user@test.example", RefreshDeadline: time.Now().Add(10 * time.Second)}}, clients.MockAuthorize{AuthorizeResponse: true}, http.StatusOK, ""},
		{"bad naked domain uri given", opts, nil, http.MethodGet, "", "/", "a.naked.domain", &cryptutil.MockEncoder{}, &sessions.MockSessionStore{Session: &sessions.State{Email: "user@test.example", RefreshDeadline: time.Now().Add(10 * time.Second)}}, clients.MockAuthorize{AuthorizeResponse: true}, http.StatusBadRequest, "{\"error\":\"bad verification uri given\"}\n"},
		{"bad naked domain uri given verify only", opts, nil, http.MethodGet, "", "/verify", "a.naked.domain", &cryptutil.MockEncoder{}, &sessions.MockSessionStore{Session: &sessions.State{Email: "user@test.example", RefreshDeadline: time.Now().Add(10 * time.Second)}}, clients.MockAuthorize{AuthorizeResponse: true}, http.StatusBadRequest, "{\"error\":\"bad verification uri given\"}\n"},
		{"bad empty verification uri given", opts, nil, http.MethodGet, "", "/", " ", &cryptutil.MockEncoder{}, &sessions.MockSessionStore{Session: &sessions.State{Email: "user@test.example", RefreshDeadline: time.Now().Add(10 * time.Second)}}, clients.MockAuthorize{AuthorizeResponse: true}, http.StatusBadRequest, "{\"error\":\"bad verification uri given\"}\n"},
		{"bad empty verification uri given verify only", opts, nil, http.MethodGet, "", "/verify", " ", &cryptutil.MockEncoder{}, &sessions.MockSessionStore{Session: &sessions.State{Email: "user@test.example", RefreshDeadline: time.Now().Add(10 * time.Second)}}, clients.MockAuthorize{AuthorizeResponse: true}, http.StatusBadRequest, "{\"error\":\"bad verification uri given\"}\n"},
		{"good post auth redirect", opts, nil, http.MethodGet, callbackQueryParam, "/", "https://some.domain.example", &cryptutil.MockEncoder{}, &sessions.MockSessionStore{Session: &sessions.State{Email: "user@test.example", RefreshDeadline: time.Now().Add(10 * time.Second)}}, clients.MockAuthorize{AuthorizeResponse: true}, http.StatusFound, "<a href=\"https://some.domain.example\">Found</a>.\n\n"},
		{"not authorized", opts, nil, http.MethodGet, "", "/", "https://some.domain.example", &cryptutil.MockEncoder{}, &sessions.MockSessionStore{Session: &sessions.State{Email: "user@test.example", RefreshDeadline: time.Now().Add(10 * time.Second)}}, clients.MockAuthorize{AuthorizeResponse: false}, http.StatusUnauthorized, "{\"error\":\"Unauthorized\"}\n"},
		{"not authorized verify endpoint", opts, nil, http.MethodGet, "", "/verify", "https://some.domain.example", &cryptutil.MockEncoder{}, &sessions.MockSessionStore{Session: &sessions.State{Email: "user@test.example", RefreshDeadline: time.Now().Add(10 * time.Second)}}, clients.MockAuthorize{AuthorizeResponse: false}, http.StatusUnauthorized, "{\"error\":\"Unauthorized\"}\n"},
		{"not authorized expired, redirect to auth", opts, nil, http.MethodGet, "", "/", "https://some.domain.example", &cryptutil.MockEncoder{}, &sessions.MockSessionStore{Session: &sessions.State{Email: "user@test.example", RefreshDeadline: time.Now().Add(-10 * time.Second)}}, clients.MockAuthorize{AuthorizeResponse: false}, http.StatusFound, ""},
		{"not authorized expired, don't redirect!", opts, nil, http.MethodGet, "", "/verify", "https://some.domain.example", &cryptutil.MockEncoder{}, &sessions.MockSessionStore{Session: &sessions.State{Email: "user@test.example", RefreshDeadline: time.Now().Add(-10 * time.Second)}}, clients.MockAuthorize{AuthorizeResponse: false}, http.StatusUnauthorized, "{\"error\":\"Unauthorized\"}\n"},
		{"not authorized because of error", opts, nil, http.MethodGet, "", "/", "https://some.domain.example", &cryptutil.MockEncoder{}, &sessions.MockSessionStore{Session: &sessions.State{Email: "user@test.example", RefreshDeadline: time.Now().Add(10 * time.Second)}}, clients.MockAuthorize{AuthorizeError: errors.New("authz error")}, http.StatusUnauthorized, "{\"error\":\"Unauthorized\"}\n"},
		{"not authorized expired, do not redirect to auth", opts, nil, http.MethodGet, "", "/verify", "https://some.domain.example", &cryptutil.MockEncoder{}, &sessions.MockSessionStore{Session: &sessions.State{Email: "user@test.example", RefreshDeadline: time.Now().Add(-10 * time.Second)}}, clients.MockAuthorize{AuthorizeResponse: false}, http.StatusUnauthorized, "{\"error\":\"Unauthorized\"}\n"},
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
			p.UpdateOptions(tt.options)
			uri := &url.URL{Path: tt.path}
			queryString := uri.Query()
			queryString.Set("donstrip", "ok")
			if tt.qp != "" {
				queryString.Set(tt.qp, "true")
			}
			if tt.verifyURI != "" {
				queryString.Set("uri", tt.verifyURI)
			}

			uri.RawQuery = queryString.Encode()

			r := httptest.NewRequest(tt.method, uri.String(), nil)
			state, err := tt.sessionStore.LoadSession(r)
			if err != nil {
				t.Fatal(err)
			}
			ctx := r.Context()
			ctx = sessions.NewContext(ctx, state, tt.ctxError)
			r = r.WithContext(ctx)
			r.Header.Set("Authorization", "Bearer blah")
			r.Header.Set("Accept", "application/json")

			w := httptest.NewRecorder()
			router := p.registerFwdAuthHandlers()
			router.ServeHTTP(w, r)
			if status := w.Code; status != tt.wantStatus {
				t.Errorf("status code: got %v want %v", status, tt.wantStatus)
				t.Errorf("\n%+v", w.Body.String())
			}

			if tt.wantBody != "" {
				body := w.Body.String()
				if diff := cmp.Diff(body, tt.wantBody); diff != "" {
					t.Errorf("wrong body\n%s", diff)
				}
			}
		})
	}
}
