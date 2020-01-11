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
	"github.com/pomerium/pomerium/proxy/clients"
	"gopkg.in/square/go-jose.v2/jwt"

	"github.com/pomerium/pomerium/internal/encoding"
	"github.com/pomerium/pomerium/internal/encoding/mock"
	"github.com/pomerium/pomerium/internal/identity"
	"github.com/pomerium/pomerium/internal/sessions"
	mstore "github.com/pomerium/pomerium/internal/sessions/mock"
)

func TestProxy_AuthenticateSession(t *testing.T) {
	t.Parallel()
	fn := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprint(w, http.StatusText(http.StatusOK))
		w.WriteHeader(http.StatusOK)
	})

	tests := []struct {
		name         string
		errOnFailure bool
		session      sessions.SessionStore
		ctxError     error
		provider     identity.Authenticator
		encoder      encoding.MarshalUnmarshaler
		refreshURL   string

		wantStatus int
	}{
		{"good", false, &mstore.Store{Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Second))}}, nil, identity.MockProvider{}, &mock.Encoder{}, "", http.StatusOK},
		{"invalid session", false, &mstore.Store{Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Second))}}, errors.New("hi"), identity.MockProvider{}, &mock.Encoder{}, "", http.StatusFound},
		{"expired", false, &mstore.Store{Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(-10 * time.Minute))}}, sessions.ErrExpired, identity.MockProvider{}, &mock.Encoder{}, "", http.StatusOK},
		{"expired and programmatic", false, &mstore.Store{Session: &sessions.State{Programmatic: true, Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(-10 * time.Minute))}}, sessions.ErrExpired, identity.MockProvider{}, &mock.Encoder{}, "", http.StatusOK},
		{"invalid session and programmatic", false, &mstore.Store{Session: &sessions.State{Programmatic: true, Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Second))}}, errors.New("hi"), identity.MockProvider{}, &mock.Encoder{}, "", http.StatusUnauthorized},
		{"expired and refreshed ok", false, &mstore.Store{Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(-10 * time.Minute))}}, sessions.ErrExpired, identity.MockProvider{}, &mock.Encoder{}, "", http.StatusOK},
		{"expired and save failed", false, &mstore.Store{SaveError: errors.New("err"), Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(-10 * time.Minute))}}, sessions.ErrExpired, identity.MockProvider{}, &mock.Encoder{}, "", http.StatusFound},
		{"expired and unmarshal failed", false, &mstore.Store{Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(-10 * time.Minute))}}, sessions.ErrExpired, identity.MockProvider{}, &mock.Encoder{UnmarshalError: errors.New("err")}, "", http.StatusFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintln(w, "REFRESH GOOD")
			}))
			defer ts.Close()
			rURL := ts.URL
			if tt.refreshURL != "" {
				rURL = tt.refreshURL
			}

			a := Proxy{
				SharedKey:              "80ldlrU2d7w+wVpKNfevk6fmb8otEx6CqOfshj2LwhQ=",
				cookieSecret:           []byte("80ldlrU2d7w+wVpKNfevk6fmb8otEx6CqOfshj2LwhQ="),
				authenticateURL:        uriParseHelper("https://authenticate.corp.example"),
				authenticateSigninURL:  uriParseHelper("https://authenticate.corp.example/sign_in"),
				authenticateRefreshURL: uriParseHelper(rURL),
				sessionStore:           tt.session,
				encoder:                tt.encoder,
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
		{"user is authorized", &mstore.Store{Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Second))}}, clients.MockAuthorize{AuthorizeResponse: true}, nil, identity.MockProvider{}, http.StatusOK},
		{"user is not authorized", &mstore.Store{Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Second))}}, clients.MockAuthorize{AuthorizeResponse: false}, nil, identity.MockProvider{}, http.StatusForbidden},
		{"ctx error", &mstore.Store{Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Second))}}, clients.MockAuthorize{AuthorizeResponse: true}, errors.New("hi"), identity.MockProvider{}, http.StatusInternalServerError},
		{"authz client error", &mstore.Store{Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Second))}}, clients.MockAuthorize{AuthorizeError: errors.New("err")}, nil, identity.MockProvider{}, http.StatusInternalServerError},
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
		{"good", &mstore.Store{Session: &sessions.State{Email: "test"}}, nil, nil, http.StatusOK, "ok"},
		{"invalid session", &mstore.Store{Session: &sessions.State{Email: "test"}}, nil, errors.New("err"), http.StatusForbidden, ""},
		{"signature failure, warn but ok", &mstore.Store{Session: &sessions.State{Email: "test"}}, errors.New("err"), nil, http.StatusOK, ""},
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
