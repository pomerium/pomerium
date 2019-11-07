package proxy

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/pomerium/pomerium/internal/identity"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/proxy/clients"
	"gopkg.in/square/go-jose.v2/jwt"
)

func TestProxy_AuthenticateSession(t *testing.T) {
	t.Parallel()
	fn := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		fmt.Fprint(w, http.StatusText(http.StatusOK))
		w.WriteHeader(http.StatusOK)
	})

	tests := []struct {
		name         string
		errOnFailure bool
		session      sessions.SessionStore
		ctxError     error
		provider     identity.Authenticator

		wantStatus int
	}{
		{"good", false, &sessions.MockSessionStore{Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Second))}}, nil, identity.MockProvider{}, http.StatusOK},
		{"invalid session", false, &sessions.MockSessionStore{Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Second))}}, errors.New("hi"), identity.MockProvider{}, http.StatusFound},
		{"expired", false, &sessions.MockSessionStore{Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(-10 * time.Minute))}}, sessions.ErrExpired, identity.MockProvider{}, http.StatusFound},
		{"expired and programmatic", false, &sessions.MockSessionStore{Session: &sessions.State{Programmatic: true, Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(-10 * time.Minute))}}, sessions.ErrExpired, identity.MockProvider{}, http.StatusUnauthorized},
		{"invalid session and programmatic", false, &sessions.MockSessionStore{Session: &sessions.State{Programmatic: true, Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Second))}}, errors.New("hi"), identity.MockProvider{}, http.StatusUnauthorized},
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
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			state, _ := tt.session.LoadSession(r)
			ctx := r.Context()
			ctx = sessions.NewContext(ctx, state, tt.ctxError)
			r = r.WithContext(ctx)
			r.Header.Set("Accept", "application/json")
			w := httptest.NewRecorder()
			got := a.AuthenticateSession(fn)
			got.ServeHTTP(w, r)
			if status := w.Code; status != tt.wantStatus {
				t.Errorf("AuthenticateSession() error = %v, wantErr %v\n%v", w.Result().StatusCode, tt.wantStatus, w.Body.String())
			}
		})
	}
}

func TestProxy_AuthorizeSession(t *testing.T) {
	t.Parallel()
	fn := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		fmt.Fprint(w, http.StatusText(http.StatusOK))
		w.WriteHeader(http.StatusOK)
	})
	tests := []struct {
		name        string
		session     sessions.SessionStore
		authzClient clients.Authorizer

		ctxError error
		provider identity.Authenticator

		wantStatus int
	}{
		{"user is authorized", &sessions.MockSessionStore{Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Second))}}, clients.MockAuthorize{AuthorizeResponse: true}, nil, identity.MockProvider{}, http.StatusOK},
		{"user is not authorized", &sessions.MockSessionStore{Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Second))}}, clients.MockAuthorize{AuthorizeResponse: false}, nil, identity.MockProvider{}, http.StatusUnauthorized},
		{"invalid session", &sessions.MockSessionStore{Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Second))}}, clients.MockAuthorize{AuthorizeResponse: true}, errors.New("hi"), identity.MockProvider{}, http.StatusUnauthorized},
		{"authz client error", &sessions.MockSessionStore{Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Second))}}, clients.MockAuthorize{AuthorizeError: errors.New("err")}, nil, identity.MockProvider{}, http.StatusInternalServerError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			a := Proxy{
				SharedKey:             "80ldlrU2d7w+wVpKNfevk6fmb8otEx6CqOfshj2LwhQ=",
				cookieSecret:          []byte("80ldlrU2d7w+wVpKNfevk6fmb8otEx6CqOfshj2LwhQ="),
				authenticateURL:       uriParseHelper("https://authenticate.corp.example"),
				authenticateSigninURL: uriParseHelper("https://authenticate.corp.example/sign_in"),
				sessionStore:          tt.session,
				AuthorizeClient:       tt.authzClient,
			}
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			state, _ := tt.session.LoadSession(r)
			ctx := r.Context()
			ctx = sessions.NewContext(ctx, state, tt.ctxError)
			r = r.WithContext(ctx)
			r.Header.Set("Accept", "application/json")
			w := httptest.NewRecorder()
			got := a.AuthorizeSession(fn)
			got.ServeHTTP(w, r)
			if status := w.Code; status != tt.wantStatus {
				t.Errorf("AuthorizeSession() error = %v, wantErr %v\n%v", w.Result().StatusCode, tt.wantStatus, w.Body.String())
			}
		})
	}
}

type mockJWTSigner struct {
	SignError error
}

// Sign implements the JWTSigner interface from the cryptutil package, but just
// base64's the inputs instead for stesting.
func (s *mockJWTSigner) Marshal(v interface{}) ([]byte, error) {

	return []byte("ok"), s.SignError
}

func TestProxy_SignRequest(t *testing.T) {
	t.Parallel()
	fn := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		fmt.Fprint(w, http.StatusText(http.StatusOK))
		w.WriteHeader(http.StatusOK)
	})

	tests := []struct {
		name    string
		session sessions.SessionStore

		signerError error
		ctxError    error

		wantStatus  int
		wantHeaders string
	}{
		{"good", &sessions.MockSessionStore{Session: &sessions.State{Email: "test"}}, nil, nil, http.StatusOK, "ok"},
		{"invalid session", &sessions.MockSessionStore{Session: &sessions.State{Email: "test"}}, nil, errors.New("err"), http.StatusForbidden, ""},
		{"signature failure, warn but ok", &sessions.MockSessionStore{Session: &sessions.State{Email: "test"}}, errors.New("err"), nil, http.StatusOK, ""},
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
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			state, _ := tt.session.LoadSession(r)
			ctx := r.Context()
			ctx = sessions.NewContext(ctx, state, tt.ctxError)
			r = r.WithContext(ctx)
			r.Header.Set("Accept", "application/json")
			w := httptest.NewRecorder()
			signer := &mockJWTSigner{SignError: tt.signerError}
			got := a.SignRequest(signer)(fn)
			got.ServeHTTP(w, r)
			if status := w.Code; status != tt.wantStatus {
				t.Errorf("SignRequest() error = %v, wantErr %v\n%v", w.Result().StatusCode, tt.wantStatus, w.Body.String())
			}
			if headers := r.Header.Get(HeaderJWT); tt.wantHeaders != headers {
				t.Errorf("SignRequest() headers = %v, want %v", headers, tt.wantHeaders)
			}
		})
	}
}

func TestProxy_SetResponseHeaders(t *testing.T) {
	t.Parallel()
	fn := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		var sb strings.Builder
		for k, v := range r.Header {
			k = strings.ToLower(k)
			for _, h := range v {
				sb.WriteString(fmt.Sprintf("%v: %v\n", k, h))
			}
		}
		fmt.Fprint(w, sb.String())
		w.WriteHeader(http.StatusOK)
	})
	tests := []struct {
		name        string
		setHeaders  map[string]string
		wantHeaders string
	}{
		{"good", map[string]string{"x-gonna": "give-it-to-ya"}, "x-gonna: give-it-to-ya\n"},
		{"nil", nil, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			r := httptest.NewRequest(http.MethodGet, "/", nil)
			w := httptest.NewRecorder()
			got := SetResponseHeaders(tt.setHeaders)(fn)
			got.ServeHTTP(w, r)
			if diff := cmp.Diff(w.Body.String(), tt.wantHeaders); diff != "" {
				t.Errorf("SignRequest() :\n %s", diff)
			}
		})
	}
}
