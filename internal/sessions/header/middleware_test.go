package header

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pomerium/pomerium/internal/encoding/ecjson"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/pkg/cryptutil"

	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/google/go-cmp/cmp"
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
		authType   string
		state      sessions.State
		wantBody   string
		wantStatus int
	}{
		{"good auth header session", "Bearer ", sessions.State{Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}, http.StatusText(http.StatusOK), http.StatusOK},
		{"empty auth header", "Bearer ", sessions.State{Expiry: jwt.NewNumericDate(time.Now().Add(-10 * time.Minute))}, "internal/sessions: session is not found\n", http.StatusUnauthorized},
		{"bad auth type", "bees ", sessions.State{Expiry: jwt.NewNumericDate(time.Now().Add(-10 * time.Minute))}, "internal/sessions: session is not found\n", http.StatusUnauthorized},
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

			if strings.Contains(tt.name, "empty") {
				encSession = []byte("")
			}
			r.Header.Set("Authorization", tt.authType+string(encSession))

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
