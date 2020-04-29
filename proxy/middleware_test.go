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
	"github.com/pomerium/pomerium/internal/encoding"
	"github.com/pomerium/pomerium/internal/encoding/jws"
	"github.com/pomerium/pomerium/internal/encoding/mock"
	"github.com/pomerium/pomerium/internal/grpc/authorize"
	"github.com/pomerium/pomerium/internal/grpc/authorize/client"
	"github.com/pomerium/pomerium/internal/identity"
	"github.com/pomerium/pomerium/internal/sessions"
	mstore "github.com/pomerium/pomerium/internal/sessions/mock"
	"gopkg.in/square/go-jose.v2/jwt"
)

func TestProxy_AuthenticateSession(t *testing.T) {
	t.Parallel()
	fn := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprint(w, http.StatusText(http.StatusOK))
		w.WriteHeader(http.StatusOK)
	})

	tests := []struct {
		name              string
		refreshRespStatus int
		errOnFailure      bool
		session           sessions.SessionStore
		ctxError          error
		provider          identity.Authenticator
		encoder           encoding.MarshalUnmarshaler
		refreshURL        string

		wantStatus int
	}{
		{"good", 200, false, &mstore.Store{Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Second))}}, nil, identity.MockProvider{}, &mock.Encoder{}, "", http.StatusOK},
		{"invalid session", 200, false, &mstore.Store{Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Second))}}, errors.New("hi"), identity.MockProvider{}, &mock.Encoder{}, "", http.StatusFound},
		{"expired", 200, false, &mstore.Store{Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(-10 * time.Minute))}}, sessions.ErrExpired, identity.MockProvider{}, &mock.Encoder{}, "", http.StatusFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.refreshRespStatus)
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
			got := a.jwtClaimMiddleware(a.AuthenticateSession(fn))
			got.ServeHTTP(w, r)
			if status := w.Code; status != tt.wantStatus {
				t.Errorf("AuthenticateSession() error = %v, wantErr %v\n%v", w.Result().StatusCode, tt.wantStatus, w.Body.String())
			}

		})
	}
}

func Test_jwtClaimMiddleware(t *testing.T) {
	email := "test@pomerium.example"
	groups := []string{"foo", "bar"}
	claimHeaders := []string{"email", "groups", "missing"}
	sharedKey := "80ldlrU2d7w+wVpKNfevk6fmb8otEx6CqOfshj2LwhQ="

	session := &sessions.State{Email: email, Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Second)), Groups: groups}
	encoder, _ := jws.NewHS256Signer([]byte(sharedKey), "https://authenticate.pomerium.example")
	state, err := encoder.Marshal(session)

	if err != nil {
		t.Errorf("failed to marshal state: %s", err)
	}

	a := Proxy{
		SharedKey:       sharedKey,
		cookieSecret:    []byte("80ldlrU2d7w+wVpKNfevk6fmb8otEx6CqOfshj2LwhQ="),
		encoder:         encoder,
		jwtClaimHeaders: claimHeaders,
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	ctx := r.Context()
	ctx = sessions.NewContext(ctx, string(state), nil)
	r = r.WithContext(ctx)
	w := httptest.NewRecorder()
	proxyHandler := a.jwtClaimMiddleware(handler)
	proxyHandler.ServeHTTP(w, r)

	t.Run("email claim", func(t *testing.T) {
		emailHeader := r.Header.Get("x-pomerium-claim-email")
		if emailHeader != email {
			t.Errorf("did not find claim email, want=%q, got=%q", email, emailHeader)
		}
	})

	t.Run("groups claim", func(t *testing.T) {
		groupsHeader := r.Header.Get("x-pomerium-claim-groups")
		if groupsHeader != strings.Join(groups, ",") {
			t.Errorf("did not find claim groups, want=%q, got=%q", groups, groupsHeader)
		}
	})

	t.Run("missing claim", func(t *testing.T) {
		absentHeader := r.Header.Get("x-pomerium-claim-missing")
		if absentHeader != "" {
			t.Errorf("found claim that should not exist, got=%q", absentHeader)
		}
	})

}

func TestProxy_AuthorizeSession(t *testing.T) {
	t.Parallel()
	fn := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprint(w, http.StatusText(http.StatusOK))
		w.WriteHeader(http.StatusOK)
	})
	tests := []struct {
		name              string
		refreshRespStatus int
		session           sessions.SessionStore
		authzClient       client.Authorizer

		ctxError error
		provider identity.Authenticator

		wantStatus int
	}{
		{"user is authorized", 200, &mstore.Store{Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Second))}}, client.MockAuthorize{AuthorizeResponse: &authorize.IsAuthorizedReply{Allow: true}}, nil, identity.MockProvider{}, http.StatusOK},
		{"user is not authorized", 200, &mstore.Store{Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Second))}}, client.MockAuthorize{AuthorizeResponse: &authorize.IsAuthorizedReply{Allow: false}}, nil, identity.MockProvider{}, http.StatusForbidden},
		{"ctx error", 200, &mstore.Store{Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Second))}}, client.MockAuthorize{AuthorizeResponse: &authorize.IsAuthorizedReply{Allow: true}}, errors.New("hi"), identity.MockProvider{}, http.StatusOK},
		{"authz client error", 200, &mstore.Store{Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Second))}}, client.MockAuthorize{AuthorizeError: errors.New("err")}, nil, identity.MockProvider{}, http.StatusInternalServerError},
		{"expired, reauth failed", 200, &mstore.Store{Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Second))}}, client.MockAuthorize{AuthorizeResponse: &authorize.IsAuthorizedReply{SessionExpired: true}}, nil, identity.MockProvider{}, http.StatusForbidden},
		//todo(bdd): it's a bit tricky to test the refresh flow
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.refreshRespStatus)
				fmt.Fprintln(w, "REFRESH GOOD")
			}))
			defer ts.Close()
			rURL := ts.URL
			a := Proxy{
				SharedKey:              "80ldlrU2d7w+wVpKNfevk6fmb8otEx6CqOfshj2LwhQ=",
				cookieSecret:           []byte("80ldlrU2d7w+wVpKNfevk6fmb8otEx6CqOfshj2LwhQ="),
				authenticateURL:        uriParseHelper("https://authenticate.corp.example"),
				authenticateSigninURL:  uriParseHelper("https://authenticate.corp.example/sign_in"),
				authenticateRefreshURL: uriParseHelper(rURL),
				sessionStore:           tt.session,
				AuthorizeClient:        tt.authzClient,
				encoder:                &mock.Encoder{},
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
				t.Errorf("SetResponseHeaders() :\n %s", diff)
			}
		})
	}
}
