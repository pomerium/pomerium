package sessions

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/pomerium/pomerium/internal/cryptutil"
	"github.com/pomerium/pomerium/internal/encoding/ecjson"
	"gopkg.in/square/go-jose.v2/jwt"
)

func TestNewContext(t *testing.T) {
	tests := []struct {
		name string
		ctx  context.Context
		t    *State
		err  error
		want context.Context
	}{
		{"simple", context.Background(), &State{Email: "bdd@pomerium.io"}, nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctxOut := NewContext(tt.ctx, tt.t, tt.err)
			stateOut, errOut := FromContext(ctxOut)
			if diff := cmp.Diff(tt.t.Email, stateOut.Email); diff != "" {
				t.Errorf("NewContext() = %s", diff)
			}
			if diff := cmp.Diff(tt.err, errOut); diff != "" {
				t.Errorf("NewContext() = %s", diff)
			}
		})
	}
}

func testAuthorizer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := FromContext(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func TestVerifier(t *testing.T) {
	fnh := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprint(w, http.StatusText(http.StatusOK))
		w.WriteHeader(http.StatusOK)
	})

	tests := []struct {
		name string
		// s     SessionStore
		state State

		cookie bool
		header bool
		param  bool

		wantBody   string
		wantStatus int
	}{
		{"good cookie session", State{Email: "user@pomerium.io", Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}, true, false, false, http.StatusText(http.StatusOK), http.StatusOK},
		{"expired cookie", State{Email: "user@pomerium.io", Expiry: jwt.NewNumericDate(time.Now().Add(-10 * time.Minute))}, true, false, false, "internal/sessions: validation failed, token is expired (exp)\n", http.StatusUnauthorized},
		{"malformed cookie", State{Email: "user@pomerium.io", Expiry: jwt.NewNumericDate(time.Now().Add(-10 * time.Minute))}, true, false, false, "internal/sessions: session is malformed\n", http.StatusUnauthorized},
		{"good auth header session", State{Email: "user@pomerium.io", Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}, false, true, false, http.StatusText(http.StatusOK), http.StatusOK},
		{"expired auth header", State{Email: "user@pomerium.io", Expiry: jwt.NewNumericDate(time.Now().Add(-10 * time.Minute))}, false, true, false, "internal/sessions: validation failed, token is expired (exp)\n", http.StatusUnauthorized},
		{"malformed auth header", State{Email: "user@pomerium.io", Expiry: jwt.NewNumericDate(time.Now().Add(-10 * time.Minute))}, false, true, false, "internal/sessions: session is malformed\n", http.StatusUnauthorized},
		{"good auth query param session", State{Email: "user@pomerium.io", Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}, false, true, true, http.StatusText(http.StatusOK), http.StatusOK},
		{"expired auth query param", State{Email: "user@pomerium.io", Expiry: jwt.NewNumericDate(time.Now().Add(-10 * time.Minute))}, false, false, true, "internal/sessions: validation failed, token is expired (exp)\n", http.StatusUnauthorized},
		{"malformed auth query param", State{Email: "user@pomerium.io", Expiry: jwt.NewNumericDate(time.Now().Add(-10 * time.Minute))}, false, false, true, "internal/sessions: session is malformed\n", http.StatusUnauthorized},
		{"no session", State{Email: "user@pomerium.io", Expiry: jwt.NewNumericDate(time.Now().Add(-10 * time.Minute))}, false, false, false, "internal/sessions: session is not found\n", http.StatusUnauthorized},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cipher, err := cryptutil.NewAEADCipherFromBase64(cryptutil.NewBase64Key())
			encoder := ecjson.New(cipher)
			if err != nil {
				t.Fatal(err)
			}
			encSession, err := encoder.Marshal(&tt.state)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(tt.name, "malformed") {
				// add some garbage to the end of the string
				encSession = append(encSession, cryptutil.NewKey()...)
			}

			cs, err := NewCookieStore(&CookieOptions{
				Name: "_pomerium",
			}, encoder)
			if err != nil {
				t.Fatal(err)
			}
			as := NewHeaderStore(encoder, "")

			qp := NewQueryParamStore(encoder, "")

			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.Header.Set("Accept", "application/json")
			w := httptest.NewRecorder()
			if tt.cookie {
				r.AddCookie(&http.Cookie{Name: "_pomerium", Value: string(encSession)})
			} else if tt.header {
				r.Header.Set("Authorization", "Bearer "+string(encSession))
			} else if tt.param {
				q := r.URL.Query()

				q.Set("pomerium_session", string(encSession))
				r.URL.RawQuery = q.Encode()
			}

			got := RetrieveSession(cs, as, qp)(testAuthorizer((fnh)))
			got.ServeHTTP(w, r)

			gotBody := w.Body.String()
			gotStatus := w.Result().StatusCode

			if diff := cmp.Diff(gotBody, tt.wantBody); diff != "" {
				t.Errorf("RetrieveSession() = %v", diff)
			}
			if diff := cmp.Diff(gotStatus, tt.wantStatus); diff != "" {
				t.Errorf("RetrieveSession() = %v", diff)
			}
		})
	}
}

func Test_contextKey_String(t *testing.T) {
	tests := []struct {
		name    string
		keyName string
		want    string
	}{
		{"simple example", "test", "context value test"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &contextKey{
				name: tt.keyName,
			}
			if got := k.String(); got != tt.want {
				t.Errorf("contextKey.String() = %v, want %v", got, tt.want)
			}
		})
	}
}
