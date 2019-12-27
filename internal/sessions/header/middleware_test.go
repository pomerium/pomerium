package header // import "github.com/pomerium/pomerium/internal/sessions/header"

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pomerium/pomerium/internal/sessions"

	"github.com/google/go-cmp/cmp"
	"github.com/pomerium/pomerium/internal/cryptutil"
	"github.com/pomerium/pomerium/internal/encoding/ecjson"
	"gopkg.in/square/go-jose.v2/jwt"
)

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
		state      sessions.State
		wantBody   string
		wantStatus int
	}{
		{"good auth header session", sessions.State{Email: "user@pomerium.io", Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}, http.StatusText(http.StatusOK), http.StatusOK},
		{"expired auth header", sessions.State{Email: "user@pomerium.io", Expiry: jwt.NewNumericDate(time.Now().Add(-10 * time.Minute))}, "internal/sessions: validation failed, token is expired (exp)\n", http.StatusUnauthorized},
		{"malformed auth header", sessions.State{Email: "user@pomerium.io", Expiry: jwt.NewNumericDate(time.Now().Add(-10 * time.Minute))}, "internal/sessions: session is malformed\n", http.StatusUnauthorized},
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

			s := NewStore(encoder, "")

			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.Header.Set("Accept", "application/json")
			w := httptest.NewRecorder()

			r.Header.Set("Authorization", "Bearer "+string(encSession))

			got := sessions.RetrieveSession(s)(testAuthorizer((fnh)))
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
