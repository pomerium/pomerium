package sessions_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"gopkg.in/square/go-jose.v2/jwt"

	"github.com/pomerium/pomerium/internal/cryptutil"
	"github.com/pomerium/pomerium/internal/encoding/jws"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/sessions/mock"
)

func TestNewContext(t *testing.T) {
	tests := []struct {
		name string
		ctx  context.Context
		t    *sessions.State
		err  error
		want context.Context
	}{
		{"simple", context.Background(), &sessions.State{Version: "v1", ID: "xyz"}, nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signer, err := jws.NewHS256Signer(cryptutil.NewKey(), "issuer")
			if err != nil {
				t.Fatal(err)
			}
			jwt, err := signer.Marshal(tt.t)
			if err != nil {
				t.Fatal(err)
			}
			ctxOut := sessions.NewContext(tt.ctx, string(jwt), tt.err)
			out, errOut := sessions.FromContext(ctxOut)
			var stateOut sessions.State
			err = signer.Unmarshal([]byte(out), &stateOut)
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(tt.err, errOut); diff != "" {
				t.Errorf("NewContext() = %s", diff)
			}
		})
	}
}

func testAuthorizer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := sessions.FromContext(r.Context())
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
		name       string
		store      mock.Store
		state      sessions.State
		wantStatus int
	}{
		{
			"empty session",
			mock.Store{LoadError: sessions.ErrNoSessionFound},
			sessions.State{Version: "v1", ID: "xyz"},
			401,
		},
		{
			"simple good load",
			mock.Store{Session: &sessions.State{Version: "v1", ID: "xyz", Subject: "hi", Expiry: jwt.NewNumericDate(time.Now().Add(time.Second))}},
			sessions.State{Version: "v1", ID: "xyz"},
			200,
		},
		{
			"session error",
			mock.Store{LoadError: errors.New("err")},
			sessions.State{Version: "v1", ID: "xyz"},
			401,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.Header.Set("Accept", "application/json")
			w := httptest.NewRecorder()

			got := sessions.RetrieveSession(tt.store)(testAuthorizer((fnh)))
			got.ServeHTTP(w, r)

			gotStatus := w.Result().StatusCode

			if diff := cmp.Diff(gotStatus, tt.wantStatus); diff != "" {
				t.Errorf("RetrieveSession() = %v", diff)
			}
		})
	}
}
