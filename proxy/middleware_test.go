package proxy

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"gopkg.in/square/go-jose.v2/jwt"

	"github.com/pomerium/pomerium/internal/encoding"
	"github.com/pomerium/pomerium/internal/encoding/jws"
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
		{"good", 200, false, &mstore.Store{Session: &sessions.State{Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Second))}}, nil, identity.MockProvider{}, &mock.Encoder{}, "", http.StatusOK},
		{"invalid session", 200, false, &mstore.Store{Session: &sessions.State{Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Second))}}, errors.New("hi"), identity.MockProvider{}, &mock.Encoder{}, "", http.StatusFound},
		{"expired", 200, false, &mstore.Store{Session: &sessions.State{Expiry: jwt.NewNumericDate(time.Now().Add(-10 * time.Minute))}}, sessions.ErrExpired, identity.MockProvider{}, &mock.Encoder{}, "", http.StatusFound},
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
				state: newAtomicProxyState(&proxyState{
					sharedKey:              "80ldlrU2d7w+wVpKNfevk6fmb8otEx6CqOfshj2LwhQ=",
					cookieSecret:           []byte("80ldlrU2d7w+wVpKNfevk6fmb8otEx6CqOfshj2LwhQ="),
					authenticateURL:        uriParseHelper("https://authenticate.corp.example"),
					authenticateSigninURL:  uriParseHelper("https://authenticate.corp.example/sign_in"),
					authenticateRefreshURL: uriParseHelper(rURL),
					sessionStore:           tt.session,
					encoder:                tt.encoder,
				}),
			}
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			state, _ := tt.session.LoadSession(r)
			ctx := r.Context()
			ctx = sessions.NewContext(ctx, state, tt.ctxError)
			r = r.WithContext(ctx)
			r.Header.Set("Accept", "application/json")
			w := httptest.NewRecorder()
			got := a.jwtClaimMiddleware(false)(a.AuthenticateSession(fn))
			got.ServeHTTP(w, r)
			if status := w.Code; status != tt.wantStatus {
				t.Errorf("AuthenticateSession() error = %v, wantErr %v\n%v", w.Result().StatusCode, tt.wantStatus, w.Body.String())
			}

		})
	}
}

func Test_jwtClaimMiddleware(t *testing.T) {
	claimHeaders := []string{"email", "groups", "missing"}
	sharedKey := "80ldlrU2d7w+wVpKNfevk6fmb8otEx6CqOfshj2LwhQ="

	session := &sessions.State{Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Second))}
	encoder, _ := jws.NewHS256Signer([]byte(sharedKey), "https://authenticate.pomerium.example")
	state, err := encoder.Marshal(session)

	if err != nil {
		t.Errorf("failed to marshal state: %s", err)
	}

	a := Proxy{
		state: newAtomicProxyState(&proxyState{
			sharedKey:       sharedKey,
			cookieSecret:    []byte("80ldlrU2d7w+wVpKNfevk6fmb8otEx6CqOfshj2LwhQ="),
			encoder:         encoder,
			jwtClaimHeaders: claimHeaders,
		}),
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	ctx := r.Context()
	ctx = sessions.NewContext(ctx, string(state), nil)
	r = r.WithContext(ctx)
	w := httptest.NewRecorder()
	proxyHandler := a.jwtClaimMiddleware(true)(handler)
	proxyHandler.ServeHTTP(w, r)

	t.Run("missing claim", func(t *testing.T) {
		absentHeader := r.Header.Get("x-pomerium-claim-missing")
		if absentHeader != "" {
			t.Errorf("found claim that should not exist, got=%q", absentHeader)
		}
	})

}
