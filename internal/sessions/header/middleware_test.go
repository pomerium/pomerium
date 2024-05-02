package header

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/internal/encoding/jws"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/pkg/cryptutil"
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
	fnh := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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
		{
			"good auth header session",
			"Pomerium ",
			sessions.State{},
			http.StatusText(http.StatusOK),
			http.StatusOK,
		},
		{
			"empty auth header",
			"Pomerium ",
			sessions.State{},
			"internal/sessions: session is not found\n",
			http.StatusUnauthorized,
		},
		{
			"bad auth type",
			"bees ",
			sessions.State{},
			"internal/sessions: session is not found\n",
			http.StatusUnauthorized,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := cryptutil.NewKey()
			encoder, err := jws.NewHS256Signer(key)
			require.NoError(t, err)
			encSession, err := encoder.Marshal(&tt.state)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(tt.name, "malformed") {
				// add some garbage to the end of the string
				encSession = append(encSession, cryptutil.NewKey()...)
			}
			s := NewStore(encoder)

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

			if diff := cmp.Diff(tt.wantBody, gotBody); diff != "" {
				t.Errorf("RetrieveSession() = %v", diff)
			}
			if diff := cmp.Diff(tt.wantStatus, gotStatus); diff != "" {
				t.Errorf("RetrieveSession() = %v", diff)
			}
		})
	}
}
