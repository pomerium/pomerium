package sessions

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp"
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

var _ SessionStore = &store{}

// Store is a mock implementation of the SessionStore interface
type store struct {
	ResponseSession string
	Session         *State
	SaveError       error
	LoadError       error
}

// ClearSession clears the ResponseSession
func (ms *store) ClearSession(http.ResponseWriter, *http.Request) {
	ms.ResponseSession = ""
}

// LoadSession returns the session and a error
func (ms store) LoadSession(*http.Request) (*State, error) {
	return ms.Session, ms.LoadError
}

// SaveSession returns a save error.
func (ms store) SaveSession(http.ResponseWriter, *http.Request, interface{}) error {
	return ms.SaveError
}

func TestVerifier(t *testing.T) {
	fnh := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprint(w, http.StatusText(http.StatusOK))
		w.WriteHeader(http.StatusOK)
	})

	tests := []struct {
		name       string
		store      store
		state      State
		wantBody   string
		wantStatus int
	}{
		{"empty session", store{}, State{}, "internal/sessions: session is not found\n", 401},
		{"simple good load", store{Session: &State{Subject: "hi"}}, State{}, "OK", 200},
		{"empty session", store{LoadError: errors.New("err")}, State{}, "err\n", 401},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.Header.Set("Accept", "application/json")
			w := httptest.NewRecorder()

			got := RetrieveSession(tt.store)(testAuthorizer((fnh)))
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
